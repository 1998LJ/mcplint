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

import ipaddress
import json
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


def result_to_json(result: GateResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
