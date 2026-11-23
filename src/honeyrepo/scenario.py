"""Scenario files: what the bait repo contains and what the attacker does."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, replace
from importlib import resources
from pathlib import Path, PurePosixPath, PureWindowsPath

# honeyrepo writes a harmless file with this name into the bait repo. The attacker reads it
# first, as a positive control that the sandbox lets it see the repo at all.
CONTROL_NAME = ".honeyrepo-control"

ATTACK_KINDS = ("exfil-file",)


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
    attack_kind: str  # a built-in attacker ("exfil-file"), or "" if attack_command is used
    attack_command: list[str]  # a custom attack command; it runs on your machine
    builtin: bool = False


def _check_relative(path: object, source: str) -> str:
    """Reject absolute paths and '..' so a scenario can only write inside its own temp directory."""
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ScenarioError(f"{source}: empty or invalid path {path!r}")
    for pure in (PurePosixPath(path), PureWindowsPath(path)):
        if pure.anchor or pure.drive or ".." in pure.parts:
            raise ScenarioError(f"{source}: unsafe path {path!r}")
    return path


def _table(data: dict, key: str, source: str, allowed: tuple[str, ...], required: bool = True) -> dict:
    value = data.get(key)
    if value is None:
        if required:
            raise ScenarioError(f"{source}: missing [{key}] section")
        return {}
    if not isinstance(value, dict):
        raise ScenarioError(f"{source}: [{key}] must be a table")
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise ScenarioError(f"{source}: unknown field(s) in [{key}]: {', '.join(unknown)}")
    return value


def _text(table: dict, key: str, where: str, source: str, required: bool = True, default: str = "") -> str:
    if key not in table:
        if required:
            raise ScenarioError(f"{source}: missing {where}")
        return default
    if not isinstance(table[key], str):
        raise ScenarioError(f"{source}: {where} must be text")
    return table[key]


def parse(text: str, source: str = "<scenario>", builtin: bool = False) -> Scenario:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as err:
        raise ScenarioError(f"{source}: not valid TOML ({err})") from err

    unknown = sorted(set(data) - {"id", "title", "description", "task", "bait", "canary", "attack"})
    if unknown:
        raise ScenarioError(f"{source}: unknown field(s): {', '.join(unknown)}")

    scenario_id = _text(data, "id", "id", source)
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", scenario_id):
        raise ScenarioError(f"{source}: id must use lowercase letters, digits and hyphens only")
    title = _text(data, "title", "title", source)

    task = _table(data, "task", source, ("prompt",), required=False)
    bait = _table(data, "bait", source, ("files",))
    files = bait.get("files")
    if not isinstance(files, dict) or not files:
        raise ScenarioError(f"{source}: [bait.files] must list at least one file")
    bait_files: dict[str, str] = {}
    for name, content in files.items():
        _check_relative(name, source)
        if PurePosixPath(name.replace("\\", "/")).as_posix() == CONTROL_NAME:
            raise ScenarioError(f"{source}: {CONTROL_NAME} is reserved for honeyrepo")
        if not isinstance(content, str):
            raise ScenarioError(f"{source}: bait file {name!r} must be text")
        bait_files[name] = content

    canary = _table(data, "canary", source, ("path", "template"))
    canary_path = _check_relative(canary.get("path"), source)
    template = _text(canary, "template", "canary.template", source)
    if "{canary}" not in template:
        # Without the marker the secret file would not contain the canary, so nothing could ever leak.
        raise ScenarioError(f"{source}: canary.template must contain {{canary}}")

    attack = _table(data, "attack", source, ("kind", "command"))
    kind = _text(attack, "kind", "attack.kind", source, required=False)
    command = attack.get("command", [])
    if bool(kind) == bool(command):
        raise ScenarioError(f"{source}: [attack] needs exactly one of 'kind' or 'command'")
    if kind and kind not in ATTACK_KINDS:
        raise ScenarioError(f"{source}: unknown attack.kind {kind!r}; known kinds: {', '.join(ATTACK_KINDS)}")
    if not isinstance(command, list) or not all(isinstance(token, str) for token in command):
        raise ScenarioError(f"{source}: attack.command must be a list of text items")

    return Scenario(
        id=scenario_id,
        title=title,
        description=_text(data, "description", "description", source, required=False).strip(),
        task_prompt=_text(task, "prompt", "task.prompt", source, required=False),
        bait_files=bait_files,
        canary_path=canary_path,
        canary_template=template,
        attack_kind=kind,
        attack_command=list(command),
        builtin=builtin,
    )


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
        return replace(parse(path.read_text(encoding="utf-8"), source=str(path)), builtin=False)
    if re.fullmatch(r"[a-z0-9][a-z0-9-]*", name_or_path):
        candidate = _builtin_dir() / f"{name_or_path}.toml"
        if candidate.is_file():
            return parse(candidate.read_text(encoding="utf-8"), source=name_or_path, builtin=True)
    raise ScenarioError(f"unknown scenario {name_or_path!r}; run 'honeyrepo list' or pass a .toml file")
