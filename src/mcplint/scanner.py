"""Scan orchestration."""

from __future__ import annotations

from pathlib import Path

from .checks import CHECKS
from .discovery import discover
from .lockfile import LOCKFILE_NAME, load_lock
from .models import InstructionFile, MCPConfigFile, ScanContext, ScanResult
from .parse import parse_config_file
from .rules.model import Rule


def root_of(paths: list[Path]) -> Path:
    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_dir():
            return path.resolve()
    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_file():
            return path.resolve().parent
    return Path.cwd()


def scan(
    paths: list[Path],
    rules: list[Rule],
    include_home: bool = False,
    online: bool = False,
) -> ScanResult:
    requested = [Path(p) for p in paths]
    config_paths, instruction_paths = discover(requested, include_home=include_home)

    configs: list[MCPConfigFile] = []
    for path in config_paths:
        parsed = parse_config_file(path)
        if parsed is not None:
            configs.append(parsed)

    instructions: list[InstructionFile] = []
    for path in instruction_paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        instructions.append(InstructionFile(path=path, text=text))

    root = root_of(requested)
    lock_path = root / LOCKFILE_NAME
    lock = load_lock(lock_path) if lock_path.is_file() else None

    ctx = ScanContext(
        configs=configs,
        instructions=instructions,
        lock=lock,
        lock_path=lock_path if lock is not None else None,
        root=root,
        online=online,
    )

    findings = []
    for rule in rules:
        check_fn = CHECKS.get(rule.check)
        if check_fn is None:
            continue
        targets: list[object] = []
        if "config" in rule.targets:
            targets.extend(configs)
        if "instructions" in rule.targets:
            targets.extend(instructions)
        if rule.once:
            targets = targets[:1]
        for target in targets:
            findings.extend(check_fn(rule, target, ctx))

    findings.sort(key=lambda f: (f.severity.rank, f.rule_id, f.file, f.line))
    return ScanResult(findings=findings, configs=configs, instructions=instructions)
