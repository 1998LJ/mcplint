"""Discovery of MCP configs and agent instruction files."""

from __future__ import annotations

import os
from pathlib import Path

REPO_CONFIGS: list[tuple[str, str]] = [
    (".mcp.json", "claude-code"),
    ("mcp.json", "generic"),
    (".cursor/mcp.json", "cursor"),
    (".vscode/mcp.json", "vscode"),
    (".windsurf/mcp.json", "windsurf"),
    ("opencode.json", "opencode"),
    ("opencode.jsonc", "opencode"),
    (".codex/config.toml", "codex"),
]

HOME_CONFIGS: list[tuple[str, str]] = [
    ("~/.cursor/mcp.json", "cursor"),
    ("~/.codeium/windsurf/mcp_config.json", "windsurf"),
    ("~/.codex/config.toml", "codex"),
    ("~/.gemini/settings.json", "gemini"),
    ("~/.config/opencode/opencode.json", "opencode"),
]

INSTRUCTION_FILES = [
    "AGENTS.md",
    "CLAUDE.md",
    ".cursorrules",
    ".windsurfrules",
    ".github/copilot-instructions.md",
]

INSTRUCTION_GLOBS = [
    "**/SKILL.md",
    ".cursor/rules/*.mdc",
]

HOME_INSTRUCTION_GLOBS = [
    "~/.claude/skills/**/SKILL.md",
    "~/.config/opencode/skills/**/SKILL.md",
    "~/.agents/skills/**/SKILL.md",
]

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    ".next",
    "target",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}

MAX_INSTRUCTION_FILES = 200

TEXT_SUFFIXES = {".md", ".mdc", ".txt"}


def _dedupe(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    for path in paths:
        key = str(path.resolve())
        if key not in seen:
            seen.add(key)
            out.append(path)
    return out


def _walk_instruction_globs(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        base = Path(dirpath)
        for name in filenames:
            if name == "SKILL.md":
                found.append(base / name)
            elif name.endswith(".mdc") and base.name == "rules" and base.parent.name == ".cursor":
                found.append(base / name)
        if len(found) >= MAX_INSTRUCTION_FILES:
            break
    return found[:MAX_INSTRUCTION_FILES]


def _discover_dir(root: Path, configs: list[Path], instructions: list[Path]) -> None:
    for rel, _client in REPO_CONFIGS:
        candidate = root / rel
        if candidate.is_file():
            configs.append(candidate)
    for rel in INSTRUCTION_FILES:
        candidate = root / rel
        if candidate.is_file():
            instructions.append(candidate)
    instructions.extend(_walk_instruction_globs(root))


def discover(
    paths: list[Path], include_home: bool = False
) -> tuple[list[Path], list[Path]]:
    """Return (config_paths, instruction_paths) for the given scan paths."""
    configs: list[Path] = []
    instructions: list[Path] = []

    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_file():
            if path.suffix.lower() in TEXT_SUFFIXES:
                instructions.append(path)
            else:
                configs.append(path)
        elif path.is_dir():
            _discover_dir(path, configs, instructions)

    if include_home:
        for pattern, _client in HOME_CONFIGS:
            candidate = Path(pattern).expanduser()
            if candidate.is_file():
                configs.append(candidate)
        for pattern in HOME_INSTRUCTION_GLOBS:
            base = Path(pattern.split("**")[0]).expanduser()
            if base.is_dir():
                instructions.extend(_walk_instruction_globs(base))

    return _dedupe(configs), _dedupe(instructions)
