"""Package reference extraction shared by checks, lockfile and AIBOM."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .models import MCPServer

NPM_RUNNERS = {"npx", "pnpx", "bunx"}
PYPI_RUNNERS = {"uvx", "pipx"}


@dataclass
class PackageSpec:
    """A third-party package referenced by a server command line."""

    kind: str  # "npm" | "pypi"
    raw: str  # token as written, e.g. "@scope/server@1.2.3"
    name: str  # normalized, version-less, lowercase
    version: str | None
    pinned: bool
    auto_approve: bool  # runner asked to skip confirmation (-y/--yes)


def version_of(token: str, kind: str) -> str | None:
    if kind == "npm":
        if token.startswith("@"):
            idx = token.rfind("@")
            return token[idx + 1 :] if idx > 0 else None
        idx = token.rfind("@")
        return token[idx + 1 :] if idx >= 0 else None
    for sep in ("==", "@"):
        if sep in token:
            return token.split(sep, 1)[1] or None
    return None


def normalize_package(token: str, kind: str = "npm") -> str:
    """Strip any version suffix so package names compare equal across syntaxes."""
    name = token.strip()
    if "==" in name:
        return name.split("==", 1)[0].lower()
    idx = name.rfind("@")
    if name.startswith("@"):
        if idx > 0:
            name = name[:idx]
    elif idx >= 0:
        name = name[:idx]
    return name.lower()


def _is_flag(token: str) -> bool:
    return token.startswith("-")


def _first_package(args: list[str]) -> str | None:
    for i, token in enumerate(args):
        if token in ("-p", "--package"):
            nxt = args[i + 1] if i + 1 < len(args) else None
            if nxt and not _is_flag(nxt):
                return nxt
        if not _is_flag(token):
            return token
    return None


def package_specs(server: MCPServer) -> list[PackageSpec]:
    """Extract npm/PyPI package references from a server's command line."""
    if not server.command:
        return []
    base = Path(server.command[0]).name.lower()
    args = server.command[1:]
    specs: list[PackageSpec] = []

    if base in NPM_RUNNERS or base in PYPI_RUNNERS:
        kind = "npm" if base in NPM_RUNNERS else "pypi"
        token = _first_package(args)
        if not token:
            return []
        version = version_of(token, kind)
        pinned = bool(version) and version != "latest"
        auto = any(a in ("-y", "--yes") for a in args)
        specs.append(
            PackageSpec(
                kind=kind,
                raw=token,
                name=normalize_package(token, kind),
                version=version if pinned else None,
                pinned=pinned,
                auto_approve=auto,
            )
        )
    return specs
