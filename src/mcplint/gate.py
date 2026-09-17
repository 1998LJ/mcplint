"""Runtime auth-enforcement probes for MCP gateways (`mcplint gate`).

Unlike `mcplint scan` (static and offline), `gate` sends a small, read-only
battery of HTTP requests to a gateway **you point it at** — localhost by
default — to verify that authentication is actually enforced on MCP and
management endpoints. Probes never execute tools and never mutate state:
they only ask "does this endpoint deny anonymous callers?".

Each probe is data (YAML under `gate_data/`), not code: one probe per known
failure class, with the CVE/advisory it comes from.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import Severity

DENY_CODES = {401, 403}
# Rejected before (or without) reaching the handler: cannot conclude either way.
INCONCLUSIVE_CODES = {202, 204, 301, 302, 303, 307, 308, 400, 404, 405, 406, 415, 422}
EVIDENCE_MAX = 160


class GateError(Exception):
    """Operational failure: bad profile, unreachable target, safety refusal."""


def builtin_gate_dir() -> Path:
    return Path(__file__).resolve().parent / "gate_data"


@dataclass
class ProbeRequest:
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None


@dataclass
class Probe:
    id: str
    title: str
    severity: Severity
    steps: list[ProbeRequest]
    remediation: str = ""
    cve: str = ""
    owasp: str = ""
    docs: str = ""
    expect: str = "deny"


@dataclass
class GateProfile:
    id: str
    name: str
    probes: list[Probe]
    default_target: str = "http://localhost:4000"
    default_headers: dict[str, str] = field(default_factory=dict)
    docs: str = ""


@dataclass
class GateFinding:
    probe_id: str
    severity: Severity
    title: str
    target: str
    status: int
    evidence: str
    remediation: str
    cve: str = ""
    owasp: str = ""

    def to_dict(self) -> dict:
        return {
            "probeId": self.probe_id,
            "severity": self.severity.value,
            "title": self.title,
            "target": self.target,
            "status": self.status,
            "evidence": self.evidence,
            "remediation": self.remediation.strip(),
            "cve": self.cve,
            "owasp": self.owasp,
        }


@dataclass
class GateNote:
    """A probe that could not reach a conclusion (informational)."""

    probe_id: str
    status: int | None
    reason: str


@dataclass
class GateResult:
    profile: str
    target: str
    findings: list[GateFinding]
    notes: list[GateNote]
    probes_run: int
    inventory: list[str] = field(default_factory=list)

    @property
    def worst_rank(self) -> int:
        return min((f.severity.rank for f in self.findings), default=99)

    def to_dict(self) -> dict:
        return {
            "tool": "mcplint gate",
            "profile": self.profile,
            "target": self.target,
            "probesRun": self.probes_run,
            "summary": {
                "total": len(self.findings),
                "inconclusive": len(self.notes),
                "worst": min(
                    (f.severity.value for f in self.findings),
                    key=lambda s: Severity(s).rank,
                    default=None,
                ),
            },
            "findings": [f.to_dict() for f in self.findings],
            "notes": [
                {"probeId": n.probe_id, "status": n.status, "reason": n.reason}
                for n in self.notes
            ],
            "inventory": self.inventory,
        }


def _parse_request(raw: dict) -> ProbeRequest:
    return ProbeRequest(
        method=str(raw.get("method", "GET")).upper(),
        path=str(raw["path"]),
        headers={str(k): str(v) for k, v in (raw.get("headers") or {}).items()},
        body=raw.get("body"),
    )


def load_profile(name: str, extra_dirs: list[Path] | None = None) -> GateProfile:
    """Load a probe profile by id (e.g. 'litellm') from gate_data/ or extra dirs."""
    for directory in [*(extra_dirs or []), builtin_gate_dir()]:
        matches = sorted(directory.glob(f"{name}.y*ml")) if directory.is_dir() else []
        if not matches:
            continue
        data = yaml.safe_load(matches[0].read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise GateError(f"{matches[0]}: profile must be a mapping")
        probes = []
        for raw in data.get("probes", []):
            if raw.get("steps"):
                steps = [_parse_request(step) for step in raw["steps"]]
            else:
                steps = [_parse_request(raw.get("request") or {})]
            probes.append(
                Probe(
                    id=str(raw["id"]),
                    title=str(raw["title"]),
                    severity=Severity(str(raw["severity"]).lower()),
                    steps=steps,
                    remediation=str(raw.get("remediation", "")),
                    cve=str(raw.get("cve", "")),
                    owasp=str(raw.get("owasp", "")),
                    docs=str(raw.get("docs", "")),
                    expect=str(raw.get("expect", "deny")),
                )
            )
        return GateProfile(
            id=str(data.get("id", name)),
            name=str(data.get("name", name)),
            probes=probes,
            default_target=str(data.get("default_target", "http://localhost:4000")),
            default_headers={
                str(k): str(v) for k, v in (data.get("default_headers") or {}).items()
            },
            docs=str(data.get("docs", "")),
        )
    raise GateError(f"unknown profile: {name!r} (looked in {directory})")


def normalize_target(target: str) -> str:
    if "://" not in target:
        target = f"http://{target}"
    parts = urllib.parse.urlsplit(target)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise GateError(f"invalid target URL: {target!r}")
    path = parts.path.rstrip("/")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def is_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def check_target_allowed(target: str, allow_host: bool) -> None:
    hostname = urllib.parse.urlsplit(target).hostname or ""
    if not allow_host and not is_loopback(hostname):
        raise GateError(
            f"refusing to probe non-loopback host {hostname!r}; "
            "pass --allow-host to confirm you own this gateway"
        )


def _render(value: str, token: str) -> str:
    return value.replace("${random}", token)


def _snip(body: str) -> str:
    text = " ".join(body.split())
    return text[:EVIDENCE_MAX] + ("…" if len(text) > EVIDENCE_MAX else "")


def _request_once(
    method: str, url: str, headers: dict[str, str], body: str | None, timeout: float
) -> tuple[int, str, dict[str, str]]:
    data = body.encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (explicit target)
            raw = resp.read(4096)
            return (
                int(resp.status),
                raw.decode("utf-8", "replace"),
                dict(resp.headers.items()),
            )
    except urllib.error.HTTPError as exc:
        raw = exc.read() if hasattr(exc, "read") else b""
        headers_out = dict(exc.headers.items()) if exc.headers else {}
        return int(exc.code), raw.decode("utf-8", "replace") if raw else "", headers_out
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise GateError(f"cannot reach {url}: {exc}") from exc


def _request(
    method: str, url: str, headers: dict[str, str], body: str | None, timeout: float
) -> tuple[int, str, dict[str, str]]:
    """Like _request_once, but follows 307/308 redirects on the same host.

    Gateways commonly redirect /mcp -> /mcp/ with a method-preserving 307,
    which urllib does not follow for POST requests. A real MCP client does.
    """
    for _ in range(3):
        status, payload, resp_headers = _request_once(method, url, headers, body, timeout)
        location = resp_headers.get("Location") or resp_headers.get("location")
        if status not in (307, 308) or not location:
            return status, payload, resp_headers
        next_url = urllib.parse.urljoin(url, location)
        if urllib.parse.urlsplit(next_url).netloc != urllib.parse.urlsplit(url).netloc:
            return status, payload, resp_headers
        url = next_url
    return status, payload, resp_headers


def _run_probe(
    probe: Probe, target: str, token: str, default_headers: dict[str, str], timeout: float
) -> tuple[int, str, list[str]] | None:
    """Run one probe's steps in order.

    Returns (status, body, trace) for the first response that was not a denial,
    or None if the gateway denied a step (401/403). MCP session ids returned by
    a step are carried into the following steps, like a real client would.
    """
    session_id: str | None = None
    trace: list[str] = []
    first: tuple[int, str] | None = None
    for step in probe.steps:
        headers = {
            **default_headers,
            **{k: _render(v, token) for k, v in step.headers.items()},
        }
        if session_id:
            headers.setdefault("Mcp-Session-Id", session_id)
        body = _render(step.body, token) if step.body else None
        status, payload, resp_headers = _request(
            step.method, target + step.path, headers, body, timeout
        )
        trace.append(f"{step.method} {step.path} -> {status}")
        if status in DENY_CODES:
            return None
        if first is None:
            first = (status, payload)
        session_id = resp_headers.get("Mcp-Session-Id") or session_id
    if first is None:  # pragma: no cover - a probe always has at least one step
        return None
    return first[0], first[1], trace


def run_gate(
    profile: GateProfile,
    target: str | None = None,
    *,
    allow_host: bool = False,
    timeout: float = 5.0,
) -> GateResult:
    """Run every probe once against `target` and evaluate the denials."""
    normalized = normalize_target(target or profile.default_target)
    check_target_allowed(normalized, allow_host)

    token = secrets.token_hex(8)
    findings: list[GateFinding] = []
    notes: list[GateNote] = []

    for probe in profile.probes:
        outcome = _run_probe(
            probe, normalized, token, profile.default_headers, timeout
        )
        if outcome is None:
            continue  # denied: authentication enforced
        status, payload, trace = outcome
        trail = "; ".join(trace)
        if 200 <= status < 300:
            findings.append(
                GateFinding(
                    probe_id=probe.id,
                    severity=probe.severity,
                    title=probe.title,
                    target=normalized + probe.steps[0].path,
                    status=status,
                    evidence=f"{trail} · {_snip(payload)}".strip(" ·"),
                    remediation=probe.remediation,
                    cve=probe.cve,
                    owasp=probe.owasp,
                )
            )
        elif status in INCONCLUSIVE_CODES:
            notes.append(
                GateNote(
                    probe_id=probe.id,
                    status=status,
                    reason=(
                        "rejected before an authentication decision could be "
                        f"observed ({trail})"
                    ),
                )
            )
        elif status >= 500:
            # The endpoint did not deny cleanly: it errored while handling an
            # unauthenticated request. Not proof of a bypass — but not a denial.
            findings.append(
                GateFinding(
                    probe_id=probe.id,
                    severity=Severity.LOW,
                    title=f"{probe.title} — endpoint errored instead of denying",
                    target=normalized + probe.steps[0].path,
                    status=status,
                    evidence=f"{trail} · {_snip(payload)}".strip(" ·"),
                    remediation=(
                        "An unauthenticated request must be rejected with 401/403; "
                        "this endpoint raised a server error instead. Check the "
                        "gateway logs for the unhandled auth exception, then: "
                        + probe.remediation.strip()
                    ),
                    cve=probe.cve,
                    owasp=probe.owasp,
                )
            )
        else:
            notes.append(
                GateNote(
                    probe_id=probe.id,
                    status=status,
                    reason=f"unexpected response ({trail})",
                )
            )

    return GateResult(
        profile=profile.id,
        target=normalized,
        findings=findings,
        notes=notes,
        probes_run=len(profile.probes),
    )


# ---------------------------------------------------------------------------
# Authenticated checks: verify what a specific key is allowed to do.
# ---------------------------------------------------------------------------

MCP_PATH = "/mcp"
MCP_PATH_ALT = "/mcp/"  # LiteLLM route patterns often only match the canonical /mcp/


@dataclass
class ReadProbe:
    """One opt-in read-only tool call that must be denied upstream."""

    tool: str
    args: dict = field(default_factory=dict)
    expect: str = "deny"


@dataclass
class AuthExpectations:
    key_env: str
    target: str = ""
    expect_tools: list[str] = field(default_factory=list)
    forbidden_tools: list[str] = field(default_factory=list)
    forbidden_servers: list[str] = field(default_factory=list)
    read_probe: ReadProbe | None = None
    # header name -> environment variable name (values are never stored literally)
    upstream_headers: dict[str, str] = field(default_factory=dict)


def load_auth_expectations(path: Path) -> AuthExpectations:
    """Load an authenticated expectations file (YAML). Keys come from env only."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise GateError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict) or not data.get("key"):
        raise GateError(f"{path}: expectations need a 'key: env/VAR_NAME' entry")
    key = str(data["key"])
    if not key.startswith("env/"):
        raise GateError(
            f"{path}: key must be 'env/VAR_NAME' — a literal key never belongs in a file"
        )
    raw_probe = data.get("read_probe")
    read_probe = None
    if isinstance(raw_probe, dict) and raw_probe.get("tool"):
        read_probe = ReadProbe(
            tool=str(raw_probe["tool"]),
            args=dict(raw_probe.get("args") or {}),
            expect=str(raw_probe.get("expect", "deny")),
        )
    upstream_headers: dict[str, str] = {}
    for header, value in (data.get("upstream_headers") or {}).items():
        if not str(value).startswith("env/"):
            raise GateError(
                f"{path}: upstream_headers[{header!r}] must be 'env/VAR_NAME' "
                "— token values never belong in a file"
            )
        upstream_headers[str(header)] = str(value)[len("env/") :]
    return AuthExpectations(
        key_env=key[len("env/") :],
        target=str(data.get("target", "")),
        expect_tools=[str(t) for t in data.get("expect_tools", []) or []],
        forbidden_tools=[str(t) for t in data.get("forbidden_tools", []) or []],
        forbidden_servers=[str(s) for s in data.get("forbidden_servers", []) or []],
        read_probe=read_probe,
        upstream_headers=upstream_headers,
    )


def _json_from_body(body: str) -> dict | None:
    """Parse a JSON or SSE (data: lines) body into the first JSON object."""
    body = body.strip()
    if not body:
        return None
    try:
        parsed = json.loads(body)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            try:
                parsed = json.loads(line[len("data:") :].strip())
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return None


def _tool_names(payload: dict | None) -> list[str] | None:
    if not isinstance(payload, dict):
        return None
    result = payload.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        return [
            str(t["name"]) for t in result["tools"] if isinstance(t, dict) and t.get("name")
        ]
    return None


def _authed_call(
    target: str,
    key: str,
    method: str,
    params: dict | None,
    extra_headers: dict[str, str],
    session_id: str | None,
    timeout: float,
    path: str = MCP_PATH,
) -> tuple[int, str, dict[str, str]]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "User-Agent": "mcplint-gate",
        "x-litellm-api-key": f"Bearer {key}",
        **extra_headers,
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    message: dict = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    if not method.startswith("notifications/"):
        message["id"] = 1
    return _request("POST", target + path, headers, json.dumps(message), timeout)


def run_auth_gate(
    expectations: AuthExpectations,
    target: str | None = None,
    *,
    allow_host: bool = False,
    timeout: float = 5.0,
) -> GateResult:
    """Verify what a single (test) key is allowed to see and reach. Read-only."""
    key = os.environ.get(expectations.key_env)
    if not key:
        raise GateError(
            f"environment variable {expectations.key_env} is not set "
            "(the key is read from the environment, never from the file)"
        )
    resolved_upstream: dict[str, str] = {}
    for header, env_name in expectations.upstream_headers.items():
        value = os.environ.get(env_name)
        if not value:
            raise GateError(
                f"environment variable {env_name} is not set "
                f"(needed for the upstream header {header!r})"
            )
        resolved_upstream[header] = value

    normalized = normalize_target(
        target or expectations.target or "http://localhost:4000"
    )
    check_target_allowed(normalized, allow_host)

    findings: list[GateFinding] = []
    notes: list[GateNote] = []

    init_params = {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "mcplint-gate", "version": "0.3.1"},
    }
    path = MCP_PATH
    status, body, resp_headers = _authed_call(
        normalized, key, "initialize", init_params, resolved_upstream, None, timeout, path
    )
    if status in DENY_CODES:
        # LiteLLM route permissions often only match the canonical /mcp/ path;
        # retry there before concluding the key is not allowed.
        alt_status, alt_body, alt_headers = _authed_call(
            normalized,
            key,
            "initialize",
            init_params,
            resolved_upstream,
            None,
            timeout,
            MCP_PATH_ALT,
        )
        if alt_status in DENY_CODES:
            source = alt_body or body
            detail = (
                _snip(source).replace(key, "<redacted>") if source else "no response body"
            )
            lowered = (source or "").lower()
            if "cloudflare" in lowered or "<html" in lowered:
                raise GateError(
                    f"the gateway's edge blocked the request (HTTP {status} on "
                    f"{MCP_PATH}, {alt_status} on {MCP_PATH_ALT}): {detail} — this "
                    "looks like a WAF/CDN bot check (e.g. Cloudflare Error 1010), "
                    "not LiteLLM: run from the corporate network/VPN or allow the "
                    "'mcplint-gate' user agent at the edge"
                )
            hint = (
                "the key is valid but not allowed to reach this MCP server (check its "
                "object_permission.mcp_servers / mcp_tool_permissions grants, and the "
                "key type's allowed_routes)"
                if 403 in (status, alt_status)
                else "the key was not accepted (401); verify the key value and header"
            )
            raise GateError(
                f"gateway rejected the test key (HTTP {status} on {MCP_PATH}, "
                f"{alt_status} on {MCP_PATH_ALT}): {detail} — {hint}"
            )
        path, status, body, resp_headers = MCP_PATH_ALT, alt_status, alt_body, alt_headers
        notes.append(
            GateNote(
                probe_id="AUTH000",
                status=alt_status,
                reason=(
                    f"{MCP_PATH} returned a denial; using the canonical "
                    f"{MCP_PATH_ALT} for this gateway"
                ),
            )
        )

    def call(
        method: str, params: dict | None, extra: dict[str, str], session_id: str | None
    ) -> tuple[int, str, dict[str, str]]:
        return _authed_call(
            normalized,
            key,
            method,
            params,
            {**resolved_upstream, **extra},
            session_id,
            timeout,
            path,
        )

    session_id = resp_headers.get("Mcp-Session-Id")
    if 200 <= status < 300 and session_id:
        call("notifications/initialized", None, {}, session_id)

    status, body, _ = call("tools/list", None, {}, session_id)
    tools = _tool_names(_json_from_body(body))
    if tools is None:
        notes.append(
            GateNote(
                probe_id="AUTH000",
                status=status,
                reason="could not parse a tools/list response with the test key",
            )
        )
        return GateResult(
            profile="auth",
            target=normalized,
            findings=findings,
            notes=notes,
            probes_run=1,
        )

    for pattern in expectations.forbidden_tools:
        hits = [t for t in tools if fnmatch.fnmatch(t.lower(), pattern.lower())]
        if hits:
            findings.append(
                GateFinding(
                    probe_id="AUTH001",
                    severity=Severity.HIGH,
                    title=f"Test key can see tools matching forbidden pattern {pattern!r}",
                    target=normalized,
                    status=status,
                    evidence=f"matched: {', '.join(hits[:8])}",
                    remediation=(
                        "Scope the key down with object_permission.mcp_tool_permissions "
                        "(or allowed_tools/disallowed_tools on the server) and remove "
                        "allow_all_keys from the MCP server registration."
                    ),
                    owasp="MCP07:2025 - Insufficient Authentication & Authorization",
                )
            )

    if expectations.expect_tools:
        expected = set(expectations.expect_tools)
        extras = sorted(set(tools) - expected)
        missing = sorted(expected - set(tools))
        if extras:
            findings.append(
                GateFinding(
                    probe_id="AUTH002",
                    severity=Severity.MEDIUM,
                    title="Test key sees tools outside the expected allowlist",
                    target=normalized,
                    status=status,
                    evidence=f"unexpected: {', '.join(extras[:8])}",
                    remediation=(
                        "Either extend expect_tools in the expectations file or tighten "
                        "the key's mcp_tool_permissions — an invited user should only see "
                        "the tools its use case needs."
                    ),
                    owasp="MCP07:2025 - Insufficient Authentication & Authorization",
                )
            )
        if missing:
            findings.append(
                GateFinding(
                    probe_id="AUTH005",
                    severity=Severity.LOW,
                    title="Expected tools are missing for the test key",
                    target=normalized,
                    status=status,
                    evidence=f"missing: {', '.join(missing[:8])}",
                    remediation=(
                        "Check the server registration and the key's permissions; a "
                        "missing expected tool usually means a config drift."
                    ),
                    owasp="MCP07:2025 - Insufficient Authentication & Authorization",
                )
            )

    for server in expectations.forbidden_servers:
        scope_status, scope_body, _ = call(
            "tools/list", None, {"x-mcp-servers": server}, session_id
        )
        names = _tool_names(_json_from_body(scope_body))
        if scope_status in DENY_CODES or (200 <= scope_status < 300 and not names):
            continue
        if 200 <= scope_status < 300 and names:
            findings.append(
                GateFinding(
                    probe_id="AUTH003",
                    severity=Severity.HIGH,
                    title=(
                        "x-mcp-servers scoping not enforced "
                        f"(requested {server!r}, got tools back)"
                    ),
                    target=normalized,
                    status=scope_status,
                    evidence=f"HTTP {scope_status}, {len(names)} tool(s): {', '.join(names[:5])}",
                    remediation=(
                        "The key must not receive tools from servers it is not granted; "
                        "check object_permission.mcp_servers for this key/team and the "
                        "server's allow_all_keys setting."
                    ),
                    owasp="MCP07:2025 - Insufficient Authentication & Authorization",
                )
            )
        else:
            notes.append(
                GateNote(
                    probe_id="AUTH003",
                    status=scope_status,
                    reason=f"scope probe for {server!r} was inconclusive",
                )
            )

    if expectations.read_probe is not None:
        probe = expectations.read_probe
        call_status, call_body, _ = call(
            "tools/call",
            {"name": probe.tool, "arguments": probe.args},
            {},
            session_id,
        )
        payload = _json_from_body(call_body)
        result = payload.get("result") if isinstance(payload, dict) else None
        denied = (
            call_status in DENY_CODES
            or call_status >= 400
            or (isinstance(payload, dict) and isinstance(payload.get("error"), dict))
            or (isinstance(result, dict) and result.get("isError") is True)
        )
        if not denied and isinstance(result, dict):
            findings.append(
                GateFinding(
                    probe_id="AUTH004",
                    severity=Severity.CRITICAL,
                    title=(
                        f"Read probe returned data for {probe.tool!r} "
                        "(the test user must not have access)"
                    ),
                    target=normalized,
                    status=call_status,
                    evidence=(
                        f"HTTP {call_status} · result present (content redacted)"
                    ),
                    remediation=(
                        "The upstream returned content for an object the test user is "
                        "not allowed to read: per-user passthrough is widening access. "
                        "Verify the Confluence/upstream permissions for the test user "
                        "and the gateway's outbound auth mode (prefer token exchange "
                        "over verbatim passthrough)."
                    ),
                    cve="CVE-2026-59822",
                    owasp="MCP07:2025 - Insufficient Authentication & Authorization",
                )
            )
        elif not denied:
            notes.append(
                GateNote(
                    probe_id="AUTH004",
                    status=call_status,
                    reason="read probe response could not be interpreted",
                )
            )

    return GateResult(
        profile="auth",
        target=normalized,
        findings=findings,
        notes=notes,
        probes_run=1 + len(expectations.forbidden_servers) + (1 if expectations.read_probe else 0),
        inventory=tools,
    )


def load_env_file(path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE env file (blank lines, # comments, optional quotes).

    Used for --env-file: keeps the key and every upstream token out of shell
    history and out of the expectations file. Existing environment variables
    take precedence (the caller should apply with setdefault).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GateError(f"cannot read env file {path}: {exc}") from exc
    values: dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        if "=" not in line:
            raise GateError(f"{path}:{lineno}: expected KEY=VALUE")
        name, _, value = line.partition("=")
        name = name.strip()
        if not name:
            raise GateError(f"{path}:{lineno}: empty variable name")
        values[name] = value.strip().strip("'\"")
    return values


def result_to_json(result: GateResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
