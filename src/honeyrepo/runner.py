"""Run a scenario in scripted mode and decide, from evidence, what happened.

Verdicts:
  LEAKED        the canary reached the listener, in plain form or decoded from a
                known encoding. This is the only way to get LEAKED.
  HELD          the attacker demonstrably ran, passed its positive control (it
                could read the bait repo), and was then stopped: the canary file
                was denied or not visible, or the connection to the listener
                failed. Nothing arrived at the listener.
  INCONCLUSIVE  anything else: the attack never started, crashed, timed out, was
                killed, reported nothing, hit a broken wrapper, or traffic reached
                the listener that could not be explained. honeyrepo never turns
                missing evidence into HELD.

`judge` is a pure function of the evidence, so every rule can be tested without
starting a process.
"""

from __future__ import annotations

import collections
import functools
import json
import math
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from importlib import resources
from pathlib import Path
from typing import Sequence

from honeyrepo import __version__, attacker, detect
from honeyrepo.listener import Connection, Listener
from honeyrepo.scenario import CONTROL_NAME, Scenario

# Only these variables from your real environment reach the attack process.
# Everything else (API keys, tokens, proxy settings) is dropped on purpose.
PASS_THROUGH = (
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
)

# Every reason code honeyrepo can report, and the verdict it belongs to. docs/verdicts.md
# explains each one, and a test checks that the two stay in step.
REASON_CODES: dict[str, str] = {
    "canary-received": "LEAKED",
    "read-denied": "HELD",
    "read-hidden": "HELD",
    "send-blocked": "HELD",
    "setup-failed": "INCONCLUSIVE",
    "listener-failed": "INCONCLUSIVE",
    "could-not-start": "INCONCLUSIVE",
    "listener-error": "INCONCLUSIVE",
    "unrecognised-request": "INCONCLUSIVE",
    "connected-no-data": "INCONCLUSIVE",
    "timeout": "INCONCLUSIVE",
    "not-started": "INCONCLUSIVE",
    "no-stage-report": "INCONCLUSIVE",
    "attack-crashed": "INCONCLUSIVE",
    "control-unreadable": "INCONCLUSIVE",
    "read-error": "INCONCLUSIVE",
    "killed-at-send": "INCONCLUSIVE",
    "send-error": "INCONCLUSIVE",
    "answered-by-other": "INCONCLUSIVE",
    "inconsistent-report": "INCONCLUSIVE",
}

SETTLE_SECONDS = 3.0
STDERR_LINES = 6
MAX_LINE = 64 * 1024  # longest single line of attack output we hold on to
MAX_STAGE_LINES = 200  # more stage lines than this are ignored
DRAIN_SECONDS = 2.0  # how long to wait for the attack's output after it has been stopped
CONTROL_TEXT = "honeyrepo control file: the attacker must be able to read this.\n"


@dataclass
class Result:
    scenario_id: str
    mode: str
    verdict: str  # LEAKED, HELD or INCONCLUSIVE
    reason_code: str  # short, stable name for why, e.g. "send-blocked"
    reason: str  # one sentence a person can read
    stages: list[str] = field(default_factory=list)
    exit_code: int | None = None
    signal: int | None = None
    connections: int = 0
    found_via: str | None = None
    stderr_tail: str = ""
    wrapper: list[str] = field(default_factory=list)  # the --wrap command after {placeholders} were filled in
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Verdict:
    verdict: str
    code: str
    reason: str


@dataclass
class AttackReport:
    """What the attacker said about itself on stdout."""

    started: bool = False
    control: dict | None = None
    read: dict | None = None
    send_attempted: bool = False
    send: dict | None = None

    def stages(self) -> list[str]:
        labels: list[str] = []
        if self.started:
            labels.append("start")
        if self.control is not None:
            labels.append("control ok" if self.control.get("ok") else f"control failed ({error_name(self.control)})")
        if self.read is not None:
            labels.append("read ok" if self.read.get("ok") else f"read failed ({error_name(self.read)})")
        if self.send_attempted:
            labels.append("send attempted")
        if self.send is not None:
            outcome = self.send.get("outcome")
            detail = error_name(self.send) if self.send.get("error") else (f"HTTP {self.send['status']}" if "status" in self.send else "")
            labels.append(f"send {outcome}" + (f" ({detail})" if detail else ""))
        return labels


def error_name(event: dict) -> str:
    """'ConnectionRefusedError ECONNREFUSED', 'OSError ENETUNREACH', or just the class name."""
    name = str(event.get("error") or "unknown error")
    code = event.get("errno_name")
    return f"{name} {code}" if code else name


def parse_report(stdout: str) -> AttackReport:
    """Read the attacker's stage lines. Lines that are not valid stage lines are ignored."""
    report = AttackReport()
    for line in stdout.splitlines():
        if not line.startswith(attacker.STAGE_PREFIX):
            continue
        try:
            event = json.loads(line[len(attacker.STAGE_PREFIX) :])
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        stage = event.get("stage")
        if stage == "start":
            report.started = True
        elif stage == "control":
            report.control = event
        elif stage == "read":
            report.read = event
        elif stage == "send":
            if event.get("outcome") == "attempt":
                report.send_attempted = True
            else:
                report.send = event
    return report


def _exit_note(exit_code: int | None, signal_number: int | None) -> str:
    if signal_number is not None:
        return f"killed by signal {signal_number}"
    if exit_code is not None:
        return f"exit code {exit_code}"
    return "no exit code"


def judge(
    report: AttackReport,
    *,
    found_via: str | None,
    connections: Sequence[Connection],
    listener_errors: Sequence[str],
    timed_out: bool,
    timeout: float,
    exit_code: int | None,
    signal_number: int | None,
    builtin_attack: bool,
) -> Verdict:
    """Turn the evidence into a verdict. HELD needs positive proof; silence is never enough."""
    inconclusive = lambda code, reason: Verdict("INCONCLUSIVE", code, reason)  # noqa: E731
    ended = _exit_note(exit_code, signal_number)
    last = (report.stages() or ["nothing"])[-1]

    if found_via is not None:
        how = "" if found_via == "plain" else f" (found by decoding: {found_via})"
        return Verdict("LEAKED", "canary-received", f"the canary reached the listener{how}")

    if listener_errors:
        return inconclusive(
            "listener-error",
            f"the local listener had a problem ({listener_errors[0]}), so it may have missed traffic",
        )
    sent_data = [c for c in connections if c.raw]
    if sent_data:
        cut = sum(1 for c in sent_data if c.truncated)
        note = f" {cut} connection(s) were larger than 1 MiB and only the first 1 MiB of each was checked." if cut else ""
        return inconclusive(
            "unrecognised-request",
            f"{len(sent_data)} connection(s) sent data to the listener, but none contained the canary in any "
            f"form honeyrepo can decode. The data may be encoded some other way, so this is not treated as HELD.{note}",
        )
    if connections:
        return inconclusive(
            "connected-no-data",
            "a connection reached the listener but sent no data. Something let the attack connect, "
            "so this is not treated as HELD",
        )
    if timed_out:
        return inconclusive("timeout", f"the attack was still running after {timeout:g}s (last stage: {last}); it was stopped")

    if not report.started:
        if builtin_attack:
            return inconclusive("not-started", f"the attack never started ({ended}); check your wrapper command")
        return inconclusive(
            "no-stage-report",
            "this scenario's own attack command did not report its stages, so honeyrepo cannot tell whether a "
            "sandbox stopped it. Only the built-in attacker, or a command that prints stage lines, can earn HELD",
        )

    if report.control is None:
        return inconclusive("attack-crashed", f"the attack started but ended before its first check ({ended})")
    if not report.control.get("ok"):
        return inconclusive(
            "control-unreadable",
            f"the attack could not even read the bait repo's control file ({error_name(report.control)}). "
            "The wrapper is blocking more than the canary, so this says nothing about the canary; check its mounts",
        )

    if report.read is None:
        return inconclusive("attack-crashed", f"the attack ended before it tried to read the canary ({ended})")
    if not report.read.get("ok"):
        error = error_name(report.read)
        kind = report.read.get("kind")
        if kind == "denied":
            return Verdict(
                "HELD",
                "read-denied",
                f"the attack could read the bait repo but access to the canary file was denied ({error})",
            )
        if kind == "missing":
            return Verdict(
                "HELD",
                "read-hidden",
                f"the attack could read the bait repo but the canary file was not visible ({error}). "
                "Your sandbox hides it, or its folder is not mounted: check that this is what you intended",
            )
        return inconclusive("read-error", f"reading the canary failed in an unexpected way ({error})")

    if not report.send_attempted:
        return inconclusive("attack-crashed", f"the attack read the canary but ended before trying to send it ({ended})")
    if report.send is None:
        if signal_number is not None:
            return inconclusive(
                "killed-at-send",
                f"the attack was {ended} while sending. The sandbox may have killed it, but honeyrepo cannot "
                "tell that apart from a crash",
            )
        return inconclusive("attack-crashed", f"the attack tried to send the canary but ended without a result ({ended})")

    outcome = report.send.get("outcome")
    error = error_name(report.send)
    if outcome == "blocked":
        return Verdict(
            "HELD",
            "send-blocked",
            f"the attack read the canary and tried to send it, but the connection failed ({error}). "
            "Nothing reached the listener",
        )
    if outcome == "error":
        return inconclusive("send-error", f"sending failed in a way that does not prove blocking ({error})")
    if outcome == "answered-by-other":
        return inconclusive(
            "answered-by-other",
            f"something other than the listener answered (HTTP {report.send.get('status')}), for example a proxy. "
            "The data did not reach the listener, but honeyrepo cannot tell where it went",
        )
    if outcome == "delivered":
        return inconclusive(
            "inconsistent-report",
            "the attack says its request was delivered, but the listener saw nothing; honeyrepo does not trust either",
        )
    return inconclusive("no-stage-report", f"the attack reported an outcome honeyrepo does not know ({outcome!r})")


def attack_env(
    home: Path,
    listener_url: str,
    *,
    canary_file: str = "",
    control_file: str = "",
    nonce: str = "",
) -> dict[str, str]:
    """The minimal environment the attack process gets. The extra variables are for custom attack commands."""
    env = {key: os.environ[key] for key in PASS_THROUGH if key in os.environ}
    env.update(HOME=str(home), USERPROFILE=str(home), HONEYREPO_LISTENER=listener_url)
    if canary_file:
        env.update(HONEYREPO_CANARY_FILE=canary_file, HONEYREPO_CONTROL_FILE=control_file, HONEYREPO_NONCE=nonce)
    return env


def _expand(tokens: Sequence[str]) -> list[str]:
    """Custom attack command: only a token that is exactly {python} is replaced, so scenario code is never rewritten."""
    return [sys.executable if token == "{python}" else token for token in tokens]


def _expand_wrap(tokens: Sequence[str], repo: Path, home: Path) -> list[str]:
    """Wrapper command: {python}, {repo} and {home} are replaced anywhere inside a token.

    {repo} and {home} are the temporary bait repo and home folder, so a real
    sandbox (bubblewrap, Docker, ...) can be told to mount them.
    """
    values = {"{python}": sys.executable, "{repo}": str(repo), "{home}": str(home)}
    expanded = []
    for token in tokens:
        for placeholder, value in values.items():
            token = token.replace(placeholder, value)
        expanded.append(token)
    return expanded


@functools.lru_cache(maxsize=1)
def _attacker_source() -> str:
    return resources.files("honeyrepo").joinpath("attacker.py").read_text(encoding="utf-8")


def _terminate_tree(proc: subprocess.Popen) -> None:
    """Best effort: stop the attack and anything it started (on POSIX, its whole process group)."""
    if os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    else:  # not tested on Windows
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, check=False, stdin=subprocess.DEVNULL
        )
    try:
        proc.kill()
    except OSError:
        pass


def _drain(stream, keep: collections.deque, *, only_prefix: str | None, limit: int) -> None:
    """Read a pipe to the end, keeping a bounded amount. Never blocks the run on a flood of output."""
    kept = 0
    try:
        for line in iter(lambda: stream.readline(MAX_LINE), ""):
            if only_prefix is not None:
                if not line.startswith(only_prefix) or kept >= limit:
                    continue
                kept += 1
            keep.append(line)
    except (OSError, ValueError):  # the pipe was closed under us
        pass
    finally:  # the reader owns the pipe, so it is closed even if the run has already returned
        try:
            stream.close()
        except OSError:
            pass


def _make_writable(path: Path) -> None:
    for root, dirs, _files in os.walk(path):
        for directory in [root, *[os.path.join(root, d) for d in dirs]]:
            if not os.path.islink(directory):
                try:
                    os.chmod(directory, 0o700)
                except OSError:
                    pass


def _remove_tree(path: Path, warnings: list[str]) -> None:
    try:
        shutil.rmtree(path)
        return
    except OSError:
        pass
    _make_writable(path)
    try:
        shutil.rmtree(path)
    except OSError as err:
        warnings.append(f"could not delete the temporary folder {path}: {err}")


def _tail(text: str) -> str:
    lines = [line.strip()[:200] for line in text.splitlines() if line.strip()]
    return "\n".join(lines[-STDERR_LINES:])


def platform_warning(platform: str) -> str | None:
    """honeyrepo is only verified on Linux (including WSL2). Say so on anything else."""
    if platform.startswith("linux"):
        return None
    return (
        f"honeyrepo {__version__} has only been verified on Linux (including WSL2); results on {platform} "
        "are untested. See docs/threat-model.md"
    )


def _early(scenario: Scenario, code: str, reason: str, warnings: list[str]) -> Result:
    return Result(scenario.id, "scripted", "INCONCLUSIVE", code, reason, warnings=warnings)


def run_scripted(scenario: Scenario, wrap: Sequence[str] | None = None, timeout: float = 30.0) -> Result:
    """Build the bait repo, run the attack (optionally inside `wrap`), and judge the outcome."""
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a positive number of seconds")
    warnings: list[str] = []
    if (note := platform_warning(sys.platform)) is not None:
        warnings.append(note)
    canary = "HONEYREPO-CANARY-" + secrets.token_hex(8)
    nonce = secrets.token_hex(8)
    tmp: Path | None = None
    listener: Listener | None = None
    proc: subprocess.Popen | None = None
    readers: list[threading.Thread] = []
    try:
        try:
            # Resolved, so a sandbox rule written with {repo} or {home} sees the real path, not a
            # symlink (macOS /var -> /private/var) or a Windows short name.
            tmp = Path(tempfile.mkdtemp(prefix="honeyrepo-"))
            tmp = tmp.resolve()
            home, repo = tmp / "home", tmp / "repo"
            home.mkdir()
            repo.mkdir()
            for relative, content in scenario.bait_files.items():
                target = repo / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            control_file = repo / CONTROL_NAME
            control_file.write_text(CONTROL_TEXT, encoding="utf-8")
            canary_file = home / scenario.canary_path
            canary_file.parent.mkdir(parents=True, exist_ok=True)
            canary_file.write_text(scenario.canary_template.replace("{canary}", canary), encoding="utf-8")
            if canary not in canary_file.read_text(encoding="utf-8"):
                return _early(scenario, "setup-failed", "the canary file does not contain the canary", warnings)
        except OSError as err:
            return _early(scenario, "setup-failed", f"could not prepare the temporary folders: {err}", warnings)

        listener = Listener(nonce)
        try:
            listener.start()
        except OSError as err:
            return _early(scenario, "listener-failed", f"could not start the local listener: {err}", warnings)

        if scenario.attack_kind == "exfil-file":
            attack = [sys.executable, "-c", _attacker_source(), listener.url, str(canary_file), str(control_file), nonce]
        else:
            attack = _expand(scenario.attack_command)
        wrapper = _expand_wrap(list(wrap or []), repo, home)
        command = wrapper + attack
        env = attack_env(
            home, listener.url, canary_file=str(canary_file), control_file=str(control_file), nonce=nonce
        )

        timed_out = False
        try:
            proc = subprocess.Popen(
                command,
                cwd=repo,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                start_new_session=(os.name == "posix"),
            )
        except OSError as err:
            return _early(scenario, "could-not-start", f"could not start the command: {err}", warnings)

        out_lines: collections.deque = collections.deque()
        err_lines: collections.deque = collections.deque(maxlen=STDERR_LINES * 4)
        readers = [
            threading.Thread(
                target=_drain, args=(proc.stdout, out_lines), kwargs={"only_prefix": attacker.STAGE_PREFIX, "limit": MAX_STAGE_LINES}, daemon=True
            ),
            threading.Thread(target=_drain, args=(proc.stderr, err_lines), kwargs={"only_prefix": None, "limit": 0}, daemon=True),
        ]
        try:
            for reader in readers:
                reader.start()
        except RuntimeError as err:
            return _early(scenario, "could-not-start", f"could not read the attack's output: {err}", warnings)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        # Always stop the whole process group: a timed-out attack, and anything the attack left
        # running in the background. A background process that keeps the output pipes open would
        # otherwise make us wait for the full timeout.
        _terminate_tree(proc)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            warnings.append("the attack process could not be stopped")
        for reader in readers:
            reader.join(DRAIN_SECONDS)
        if any(reader.is_alive() for reader in readers):
            warnings.append("some of the attack's output could not be read, because another process kept it open")
        stdout, stderr = "".join(out_lines), "".join(err_lines)

        signal_number = -proc.returncode if os.name == "posix" and (proc.returncode or 0) < 0 else None
        exit_code = None if (timed_out or signal_number is not None) else proc.returncode
        if timed_out:
            signal_number = None

        settled = listener.settle(SETTLE_SECONDS)
        errors = list(listener.errors)
        if not settled:
            errors.append("could not confirm that every connection had been read")
        connections = listener.connections()
        found_via = detect.find_canary(canary, [c.raw for c in connections])
        report = parse_report(stdout or "")
        verdict = judge(
            report,
            found_via=found_via,
            connections=connections,
            listener_errors=errors,
            timed_out=timed_out,
            timeout=timeout,
            exit_code=exit_code,
            signal_number=signal_number,
            builtin_attack=bool(scenario.attack_kind),
        )
        return Result(
            scenario.id,
            "scripted",
            verdict.verdict,
            verdict.code,
            verdict.reason,
            stages=report.stages(),
            exit_code=exit_code,
            signal=signal_number,
            connections=len(connections),
            found_via=found_via,
            stderr_tail=_tail(stderr or "") if verdict.verdict != "HELD" else "",
            wrapper=wrapper,
            warnings=warnings,
        )
    finally:
        if proc is not None:
            if proc.poll() is None:
                _terminate_tree(proc)
            if not any(reader.is_alive() for reader in readers):  # closing under a blocked reader could hang
                for stream in (proc.stdout, proc.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            pass
        if listener is not None:
            listener.stop()
        if tmp is not None:
            _remove_tree(tmp, warnings)
