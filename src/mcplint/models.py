"""Core data models for mcplint."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def severity_from(value: str) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError as exc:
        raise ValueError(f"unknown severity: {value!r}") from exc


@dataclass
class MCPServer:
    """A single MCP server entry, normalized across client config formats."""

    name: str
    transport: str = "stdio"
    command: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_remote(self) -> bool:
        return bool(self.url)


@dataclass
class MCPConfigFile:
    """A discovered MCP client configuration file."""

    path: Path
    client: str
    servers: list[MCPServer]
    raw_text: str


@dataclass
class InstructionFile:
    """An agent instruction / skill file (SKILL.md, AGENTS.md, .cursorrules...)."""

    path: Path
    text: str


@dataclass
class Finding:
    """One security finding produced by a rule."""

    rule_id: str
    severity: Severity
    title: str
    message: str
    file: str
    server: str | None = None
    line: int = 1
    owasp: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
            "file": self.file,
            "server": self.server,
            "line": self.line,
            "owasp": self.owasp,
            "remediation": self.remediation,
        }


@dataclass
class ScanContext:
    """Everything a check function may need beyond its direct target."""

    configs: list[MCPConfigFile]
    instructions: list[InstructionFile]
    lock: dict[str, Any] | None
    lock_path: Path | None
    root: Path
    online: bool
    cache: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    findings: list[Finding]
    configs: list[MCPConfigFile]
    instructions: list[InstructionFile]

    @property
    def worst_rank(self) -> int:
        if not self.findings:
            return 99
        return min(f.severity.rank for f in self.findings)

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "scanned": {
                "configs": [str(c.path) for c in self.configs],
                "instructionFiles": [str(i.path) for i in self.instructions],
            },
            "summary": {
                "total": len(self.findings),
                **self.counts(),
            },
        }
