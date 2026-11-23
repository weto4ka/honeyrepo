"""Scenario files: what the bait repo contains and what the attacker does."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path, PurePosixPath, PureWindowsPath


class ScenarioError(ValueError):
    """The scenario file is malformed, incomplete or unsafe."""


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    description: str
    task_prompt: str  # used by live mode (not built yet): the harmless task given to a real agent
    bait_files: dict[str, str]
    canary_path: str  # relative to the throwaway HOME
    canary_template: str  # "{canary}" is replaced with a fresh fake secret on every run
    attack_command: list[str]  # what a fully compromised agent would do (scripted mode)


def _check_relative(path: str, source: str) -> str:
    """Reject absolute paths and '..' so a scenario can only write inside its own temp directory."""
    if not isinstance(path, str) or not path:
        raise ScenarioError(f"{source}: empty or invalid path {path!r}")
    for pure in (PurePosixPath(path), PureWindowsPath(path)):
        if pure.anchor or ".." in pure.parts:
            raise ScenarioError(f"{source}: unsafe path {path!r}")
    return path


def parse(text: str, source: str = "<scenario>") -> Scenario:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as err:
        raise ScenarioError(f"{source}: not valid TOML ({err})") from err
    try:
        bait = {_check_relative(p, source): c for p, c in data["bait"]["files"].items()}
        scenario = Scenario(
            id=data["id"],
            title=data["title"],
            description=data.get("description", "").strip(),
            task_prompt=data.get("task", {}).get("prompt", ""),
            bait_files=bait,
            canary_path=_check_relative(data["canary"]["path"], source),
            canary_template=data["canary"]["template"],
            attack_command=list(data["attack"]["command"]),
        )
    except (KeyError, TypeError, AttributeError) as err:
        raise ScenarioError(f"{source}: missing or malformed field {err}") from err
    if not scenario.attack_command:
        raise ScenarioError(f"{source}: attack.command is empty")
    return scenario


def _builtin_dir():
    return resources.files("honeyrepo") / "scenarios"


def list_builtin() -> list[str]:
    return sorted(
        item.name[: -len(".toml")] for item in _builtin_dir().iterdir() if item.name.endswith(".toml")
    )


def load(name_or_path: str) -> Scenario:
    """Load a scenario from a .toml file path, or by the name of a built-in scenario."""
    path = Path(name_or_path)
    if path.suffix == ".toml" and path.is_file():
        return parse(path.read_text(encoding="utf-8"), source=str(path))
    if re.fullmatch(r"[a-z0-9][a-z0-9-]*", name_or_path):
        candidate = _builtin_dir() / f"{name_or_path}.toml"
        if candidate.is_file():
            return parse(candidate.read_text(encoding="utf-8"), source=name_or_path)
    raise ScenarioError(f"unknown scenario {name_or_path!r}; run 'honeyrepo list' or pass a .toml file")
