"""Built-in check implementations, dispatched by ``rule.check``."""

from __future__ import annotations

import json
import re
import stat
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .lockfile import verify_lock
from .models import (
    Finding,
    InstructionFile,
    MCPConfigFile,
    ScanContext,
    Severity,
)
from .packages import normalize_package, package_specs
from .rules.model import Rule

CheckFn = Callable[[Rule, Any, ScanContext], list[Finding]]
CHECKS: dict[str, CheckFn] = {}


def check(name: str) -> Callable[[CheckFn], CheckFn]:
    def decorator(fn: CheckFn) -> CheckFn:
        CHECKS[name] = fn
        return fn

    return decorator


def _finding(
    rule: Rule,
    path: Any,
    message: str,
    server: str | None = None,
    line: int = 1,
    severity: Severity | None = None,
) -> Finding:
    return Finding(
        rule_id=rule.id,
        severity=severity or rule.severity,
        title=rule.title,
        message=message,
        file=str(path),
        server=server,
        line=max(1, line),
        owasp=rule.owasp or None,
        remediation=rule.remediation or None,
    )


def _line_of(text: str, needle: str) -> int:
    if not needle:
        return 1
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text.count("\n", 0, idx) + 1


def _is_env_ref(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    if "${" in stripped:
        return True
    return stripped.startswith("$") and " " not in stripped


def _looks_placeholder(value: str) -> bool:
    placeholders = {
        "changeme",
        "change-me",
        "your-key-here",
        "your_api_key",
        "your-api-key",
        "placeholder",
        "example",
        "todo",
        "none",
        "null",
    }
    lowered = value.strip().lower()
    if lowered in placeholders:
        return True
    markers = (
        "your_",
        "your-",
        "xxx",
        "dummy",
        "placeholder",
        "example",
        "sample",
        "fake",
        "changeme",
        "change-me",
        "insert_",
        "replace_",
        "todo",
        "<",
        ">",
    )
    return any(marker in lowered for marker in markers)


def _first_matching_pattern(value: str, patterns: list[dict[str, Any]]) -> str | None:
    for pattern in patterns:
        try:
            if re.search(pattern["regex"], value):
                return str(pattern["name"])
        except re.error:
            continue
    return None


def _is_local_host(hostname: str | None) -> bool:
    return hostname in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _is_internal_host(hostname: str | None) -> bool:
    """Private, loopback, link-local and dev TLDs: unencrypted transport is
    less exposed than on the public internet, so findings rank lower."""
    import ipaddress

    if not hostname:
        return False
    lowered = hostname.lower()
    if "." not in lowered:
        return True
    if lowered == "localhost" or lowered.endswith(
        (".local", ".internal", ".test", ".docker.internal", ".localhost")
    ):
        return True
    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


@check("secrets_in_config")
def secrets_in_config(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    patterns = rule.params.get("patterns", [])
    suspicious_key = rule.params.get("suspicious_env_key", "")
    min_len = int(rule.params.get("min_len", 12))

    def scan_value(server_name: str, key: str, value: str) -> None:
        if _is_env_ref(value) or _looks_placeholder(value):
            return
        matched = _first_matching_pattern(value, patterns)
        line = _line_of(target.raw_text, key)
        if matched:
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"{matched} found in env.{key}",
                    server=server_name,
                    line=line,
                )
            )
        elif suspicious_key and re.search(suspicious_key, key) and len(value) >= min_len:
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"literal value for sensitive env.{key} (length {len(value)}) — "
                    "use an env reference instead",
                    server=server_name,
                    line=line,
                    severity=Severity.HIGH,
                )
            )

    for server in target.servers:
        for key, value in server.env.items():
            scan_value(server.name, key, value)
        joined = " ".join(server.command)
        matched = (
            _first_matching_pattern(joined, patterns) if not _looks_placeholder(joined) else None
        )
        if matched:
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"{matched} found in args of server '{server.name}'",
                    server=server.name,
                    line=_line_of(target.raw_text, server.name),
                )
            )
        for header, value in server.headers.items():
            if _is_env_ref(value) or _looks_placeholder(value):
                continue
            matched = _first_matching_pattern(value, patterns)
            if matched:
                findings.append(
                    _finding(
                        rule,
                        target.path,
                        f"{matched} found in header '{header}' of server '{server.name}'",
                        server=server.name,
                        line=_line_of(target.raw_text, header),
                    )
                )
    return findings


@check("file_permissions")
def file_permissions(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    try:
        mode = stat.S_IMODE(target.path.stat().st_mode)
    except OSError:
        return []
    has_secrets = any(server.env for server in target.servers)
    if mode & 0o002:
        return [
            _finding(
                rule,
                target.path,
                f"config is world-writable (mode {oct(mode)}) — any local process can "
                "tamper with it (rug-pull vector)",
                severity=Severity.HIGH,
            )
        ]
    if (mode & 0o044) and has_secrets:
        return [
            _finding(
                rule,
                target.path,
                f"config is group/world-readable (mode {oct(mode)}) and contains "
                "credentials — restrict with chmod 600",
            )
        ]
    return []


@check("unpinned_package")
def unpinned_package(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for server in target.servers:
        for spec in package_specs(server):
            if spec.pinned:
                continue
            severity = Severity.HIGH if spec.auto_approve else rule.severity
            extra = " and auto-approved (-y/--yes)" if spec.auto_approve else ""
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"'{spec.raw}' is not pinned to a version{extra} — a malicious or "
                    "broken release is picked up on every run",
                    server=server.name,
                    line=_line_of(target.raw_text, spec.raw),
                    severity=severity,
                )
            )
    return findings


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


@check("typosquat_package")
def typosquat_package(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    known = [str(k) for k in rule.params.get("known_packages", [])]
    max_distance = int(rule.params.get("max_distance", 1))

    def alpha(name: str) -> str:
        return re.sub(r"[^a-z0-9]", "", name.lower())

    known_full = {normalize_package(k): k for k in known}
    known_alpha = {alpha(k): k for k in known}

    findings: list[Finding] = []
    for server in target.servers:
        for spec in package_specs(server):
            name = spec.name
            if not name or name in known_full or alpha(name) in known_alpha:
                continue
            for known_name, original in known_full.items():
                distance = _levenshtein(alpha(name), alpha(known_name))
                if 1 <= distance <= max_distance:
                    findings.append(
                        _finding(
                            rule,
                            target.path,
                            f"'{spec.raw}' is {distance} edit(s) away from popular package "
                            f"'{original}' — possible typosquat",
                            server=server.name,
                            line=_line_of(target.raw_text, spec.raw),
                        )
                    )
                    break
    return findings


@check("insecure_remote_transport")
def insecure_remote_transport(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for server in target.servers:
        if not server.url:
            continue
        parsed = urllib.parse.urlparse(server.url)
        if parsed.scheme == "http" and not _is_local_host(parsed.hostname):
            severity = Severity.LOW if _is_internal_host(parsed.hostname) else rule.severity
            scope = "internal host" if severity is Severity.LOW else "public host"
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"remote endpoint '{server.url}' uses plain HTTP ({scope}) — tool calls and "
                    "results travel unencrypted",
                    server=server.name,
                    line=_line_of(target.raw_text, server.url),
                    severity=severity,
                )
            )
    return findings


@check("remote_without_auth")
def remote_without_auth(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    auth_pattern = rule.params.get("auth_env_pattern", "")
    findings: list[Finding] = []
    for server in target.servers:
        if not server.url:
            continue
        parsed = urllib.parse.urlparse(server.url)
        if _is_local_host(parsed.hostname):
            continue
        has_auth = any(key.lower() == "authorization" for key in server.headers)
        if not has_auth and auth_pattern:
            has_auth = any(re.search(auth_pattern, key) for key in server.env)
            if not has_auth:
                has_auth = any(re.search(auth_pattern, key) for key in server.headers)
        if not has_auth:
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"remote endpoint '{server.url}' references no authentication material "
                    "(no Authorization header, no token/key env)",
                    server=server.name,
                    line=_line_of(target.raw_text, server.url),
                )
            )
    return findings


@check("filesystem_overreach")
def filesystem_overreach(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    dangerous = {str(p) for p in rule.params.get("dangerous_paths", [])}
    hints = [str(h).lower() for h in rule.params.get("filesystem_hints", [])]
    findings: list[Finding] = []
    for server in target.servers:
        haystack = " ".join(server.command).lower()
        is_filesystem = any(hint in haystack for hint in hints)
        if not is_filesystem:
            continue
        for token in server.command[1:]:
            if token in dangerous:
                findings.append(
                    _finding(
                        rule,
                        target.path,
                        f"filesystem server '{server.name}' is scoped to '{token}' — "
                        "it can read and write far beyond the project workspace",
                        server=server.name,
                        line=_line_of(target.raw_text, token),
                    )
                )
    return findings


@check("shell_execution_server")
def shell_execution_server(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    bins = {str(b).lower() for b in rule.params.get("shell_bins", [])}
    hints = [str(h).lower() for h in rule.params.get("shell_hints", [])]
    findings: list[Finding] = []
    for server in target.servers:
        if not server.command:
            continue
        base = Path(server.command[0]).name.lower()
        haystack = " ".join(server.command).lower()
        if base in bins:
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"server '{server.name}' spawns a shell ('{server.command[0]}') — "
                    "it can execute arbitrary commands on this machine",
                    server=server.name,
                    line=_line_of(target.raw_text, server.name),
                )
            )
        elif any(hint in haystack for hint in hints):
            findings.append(
                _finding(
                    rule,
                    target.path,
                    f"server '{server.name}' looks like a command-execution server",
                    server=server.name,
                    line=_line_of(target.raw_text, server.name),
                )
            )
    return findings


@check("injection_markers")
def injection_markers(rule: Rule, target: Any, ctx: ScanContext) -> list[Finding]:
    if isinstance(target, InstructionFile):
        text = target.text
        path = target.path
    elif isinstance(target, MCPConfigFile):
        text = target.raw_text
        path = target.path
    else:
        return []

    patterns = rule.params.get("patterns", [])
    hits: list[tuple[str, int]] = []
    high_confidence = False
    for pattern in patterns:
        try:
            match = re.search(str(pattern["regex"]), text)
        except re.error:
            continue
        if match:
            hits.append((str(pattern["name"]), match.start()))
            high_confidence = high_confidence or bool(pattern.get("high_confidence"))

    if not hits:
        return []

    severity = Severity.HIGH if (high_confidence or len(hits) >= 2) else Severity.LOW
    findings: list[Finding] = []
    for name, position in hits[:5]:
        findings.append(
            _finding(
                rule,
                path,
                f"possible prompt-injection indicator ({name}); {len(hits)} indicator(s) found "
                "in this file",
                line=text.count("\n", 0, position) + 1,
                severity=severity,
            )
        )
    return findings


_HIDDEN_NAMES = {
    0x00AD: "soft hyphen",
    0x200B: "zero-width space",
    0x200C: "zero-width non-joiner",
    0x200D: "zero-width joiner",
    0x200E: "left-to-right mark",
    0x200F: "right-to-left mark",
    0x202A: "bidi embedding",
    0x202B: "bidi embedding",
    0x202C: "bidi pop",
    0x202D: "bidi override",
    0x202E: "bidi override",
    0x2060: "word joiner",
    0x2061: "function application",
    0x2062: "invisible times",
    0x2063: "invisible separator",
    0x2064: "invisible plus",
    0xFEFF: "byte order mark",
}


@check("hidden_unicode")
def hidden_unicode(rule: Rule, target: Any, ctx: ScanContext) -> list[Finding]:
    if isinstance(target, InstructionFile):
        text = target.text
        path = target.path
    elif isinstance(target, MCPConfigFile):
        text = target.raw_text
        path = target.path
    else:
        return []

    codepoints = {int(cp, 16) for cp in rule.params.get("codepoints", [])}
    first_seen: dict[int, int] = {}
    for index, char in enumerate(text):
        value = ord(char)
        if value in codepoints and value not in first_seen:
            first_seen[value] = index

    findings: list[Finding] = []
    for value, position in sorted(first_seen.items()):
        name = _HIDDEN_NAMES.get(value, "hidden character")
        findings.append(
            _finding(
                rule,
                path,
                f"hidden unicode U+{value:04X} ({name}) — invisible text can smuggle "
                "instructions past human review",
                line=text.count("\n", 0, position) + 1,
            )
        )
    return findings


@check("server_name_shadowing")
def server_name_shadowing(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    if ctx.cache.get("shadowing_done"):
        return []
    ctx.cache["shadowing_done"] = True

    by_name: dict[str, list[MCPConfigFile]] = {}
    for config in ctx.configs:
        for server in config.servers:
            by_name.setdefault(server.name.lower(), []).append(config)

    findings: list[Finding] = []
    for name, configs in by_name.items():
        files = {str(c.path) for c in configs}
        if len(files) > 1:
            findings.append(
                _finding(
                    rule,
                    configs[0].path,
                    f"server name '{name}' is defined in {len(files)} different configs "
                    "(tool shadowing risk)",
                    server=name,
                )
            )
    return findings


@check("lockfile_drift")
def lockfile_drift(rule: Rule, target: MCPConfigFile, ctx: ScanContext) -> list[Finding]:
    if ctx.cache.get("lock_drift_done"):
        return []
    ctx.cache["lock_drift_done"] = True
    if not ctx.lock:
        return []
    return verify_lock(ctx.lock, ctx.configs, ctx.root, rule)


def _osv_query(kind: str, name: str, version: str) -> list[dict[str, Any]]:
    ecosystem = "npm" if kind == "npm" else "PyPI"
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    request = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "mcplint"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []
    vulns = body.get("vulns", [])
    return vulns if isinstance(vulns, list) else []


def _osv_severity(vuln: dict[str, Any]) -> Severity:
    database_specific = vuln.get("database_specific") or {}
    label = str(database_specific.get("severity", "")).lower()
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }.get(label, Severity.MEDIUM)


@check("known_vulnerable_dependency")
def known_vulnerable_dependency(
    rule: Rule, target: MCPConfigFile, ctx: ScanContext
) -> list[Finding]:
    if not ctx.online:
        return []
    findings: list[Finding] = []
    for server in target.servers:
        for spec in package_specs(server):
            if not spec.pinned or not spec.version:
                continue
            cache_key = f"osv:{spec.kind}:{spec.name}@{spec.version}"
            if cache_key not in ctx.cache:
                ctx.cache[cache_key] = _osv_query(spec.kind, spec.name, spec.version)
            for vuln in ctx.cache[cache_key]:
                vuln_id = str(vuln.get("id", "OSV"))
                summary = str(vuln.get("summary", "")).strip()
                truncated = (summary[:120] + "...") if len(summary) > 120 else summary
                findings.append(
                    _finding(
                        rule,
                        target.path,
                        f"{spec.name}@{spec.version} matches {vuln_id}"
                        + (f": {truncated}" if truncated else ""),
                        server=server.name,
                        line=_line_of(target.raw_text, spec.raw),
                        severity=_osv_severity(vuln),
                    )
                )
    return findings
