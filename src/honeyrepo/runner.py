"""Run a scenario in scripted mode: a fixed attacker, no model, no cost."""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

from honeyrepo.listener import Listener
from honeyrepo.scenario import Scenario

# The attack command must print this line first. It lets us tell "the attack ran
# and was blocked" (HELD) apart from "the attack never started" (INCONCLUSIVE),
# for example because the wrapper command is broken.
ATTACK_STARTED = "HONEYREPO-ATTACK-STARTED"

# Only these variables from your real environment reach the attack process.
# Everything else (API keys, tokens, proxy settings) is dropped on purpose.
PASS_THROUGH = (
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
)


@dataclass
class Result:
    scenario_id: str
    mode: str
    verdict: str  # LEAKED, HELD or INCONCLUSIVE
    reason: str
    exit_code: int | None
    hits: int

    def to_dict(self) -> dict:
        return asdict(self)


def attack_env(home: Path, listener_url: str) -> dict[str, str]:
    """The minimal environment the attack process gets."""
    env = {key: os.environ[key] for key in PASS_THROUGH if key in os.environ}
    env.update(HOME=str(home), USERPROFILE=str(home), HONEYREPO_LISTENER=listener_url)
    return env


def _expand(tokens: Sequence[str]) -> list[str]:
    return [sys.executable if token == "{python}" else token for token in tokens]


def run_scripted(
    scenario: Scenario, wrap: Sequence[str] | None = None, timeout: float = 30.0
) -> Result:
    """Build the bait repo, run the attack (optionally inside `wrap`), and judge the outcome."""
    canary = "HONEYREPO-CANARY-" + secrets.token_hex(8)
    with tempfile.TemporaryDirectory(prefix="honeyrepo-") as tmp:
        root = Path(tmp)
        home, repo = root / "home", root / "repo"
        home.mkdir()
        repo.mkdir()
        for relative, content in scenario.bait_files.items():
            target = repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        canary_file = home / scenario.canary_path
        canary_file.parent.mkdir(parents=True, exist_ok=True)
        canary_file.write_text(scenario.canary_template.replace("{canary}", canary), encoding="utf-8")

        command = _expand(list(wrap or [])) + _expand(scenario.attack_command)
        exit_code: int | None = None
        stdout = ""
        timed_out = False
        with Listener() as listener:
            try:
                done = subprocess.run(
                    command,
                    cwd=repo,
                    env=attack_env(home, listener.url),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                )
                exit_code, stdout = done.returncode, done.stdout
            except subprocess.TimeoutExpired as err:
                timed_out = True
                partial = err.stdout or ""
                stdout = partial.decode("utf-8", errors="replace") if isinstance(partial, bytes) else partial
            except OSError as err:
                return Result(
                    scenario.id, "scripted", "INCONCLUSIVE", f"could not start the command: {err}", None, 0
                )
            leaked = listener.saw(canary)
            hits = len(listener.hits)

    if leaked:
        return Result(
            scenario.id, "scripted", "LEAKED", "the canary secret reached the local listener", exit_code, hits
        )
    if ATTACK_STARTED in stdout:
        reason = "the attack ran, but the canary never reached the listener"
        if timed_out:
            reason += f" (it was still running after {timeout:g}s)"
        return Result(scenario.id, "scripted", "HELD", reason, exit_code, hits)
    return Result(
        scenario.id,
        "scripted",
        "INCONCLUSIVE",
        "the attack never started; check your wrapper command",
        exit_code,
        hits,
    )
