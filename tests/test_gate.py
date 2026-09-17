"""Tests for the runtime gate probes (`mcplint gate`)."""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml
from typer.testing import CliRunner

from mcplint.cli import app
from mcplint.gate import (
    GateError,
    _render,
    load_auth_expectations,
    load_profile,
    run_auth_gate,
    run_gate,
)

runner = CliRunner()
KEY = "sk-valid-test-key"
TOOLS = ["confluence.search", "confluence.get_page"]
SEEN: list[dict] = []


class _Handler(BaseHTTPRequestHandler):
    mode = "patched"

    def log_message(self, *args):  # keep test output clean
        pass

    def _send(self, code: int, payload: dict | None = None) -> None:
        body = json.dumps(payload or {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if code == 200 and self.path == "/mcp":
            self.send_header("Mcp-Session-Id", "test-session-1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _authed(self) -> bool:
        for name in ("Authorization", "x-litellm-api-key"):
            value = (self.headers.get(name) or "").removeprefix("Bearer ")
            if value == KEY:
                return True
        return False

    def _record(self) -> None:
        if self.path == "/mcp":
            SEEN.append({"session": self.headers.get("Mcp-Session-Id")})

    def do_GET(self):  # noqa: N802
        if self.mode == "missing":
            self._send(404)
        elif self.path == "/sse":
            self._send(200 if self.mode == "vulnerable" else 401)
        elif self.path == "/v1/mcp/server":
            self._send(200 if (self.mode == "vulnerable" or self._authed()) else 401)
        else:
            self._send(404)

    def do_POST(self):  # noqa: N802
        self._record()
        if self.mode == "missing":
            self._send(404)
        elif self.path == "/mcp" and self.mode == "redirect":
            self.send_response(307)
            self.send_header("Location", "/mcp/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path in ("/mcp", "/mcp/"):
            if self.mode == "erroring":
                self._send(500, {"detail": "Internal Server Error"})
                return
            if not (self.mode in ("vulnerable", "redirect") or self._authed()):
                self._send(401)
                return
            method = self._body().get("method", "")
            if method == "tools/list":
                if self.headers.get("x-mcp-servers") and self.mode != "leaky_scope":
                    self._send(401)
                    return
                tools = [{"name": name} for name in TOOLS]
                if self.mode == "overexposed":
                    tools.append({"name": "confluence.delete_page"})
                self._send(200, {"jsonrpc": "2.0", "result": {"tools": tools}})
            elif method == "tools/call":
                if self.mode == "leaky_read":
                    self._send(
                        200,
                        {
                            "jsonrpc": "2.0",
                            "result": {
                                "content": [{"type": "text", "text": "redacted-secret"}]
                            },
                        },
                    )
                else:
                    self._send(
                        200, {"jsonrpc": "2.0", "result": {"isError": True, "content": []}}
                    )
            else:
                self._send(200, {})
        elif self.path == "/mcp-rest/test/connection":
            self._send(401)  # admin-only in every version we support
        else:
            self._send(404)


@contextmanager
def gateway(mode: str):
    handler = type("Handler", (_Handler,), {"mode": mode})
    SEEN.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def test_profile_loads_with_probes() -> None:
    profile = load_profile("litellm")
    assert len(profile.probes) >= 7
    assert all(p.remediation for p in profile.probes)
    assert {p.id for p in profile.probes} >= {"GATE001", "GATE005"}


def test_render_replaces_random_token() -> None:
    assert _render("Bearer ${random}", "abc123") == "Bearer abc123"


def test_patched_gateway_has_no_findings() -> None:
    profile = load_profile("litellm")
    with gateway("patched") as target:
        result = run_gate(profile, target)
    assert result.findings == []
    assert result.probes_run == len(profile.probes)


def test_vulnerable_gateway_flags_auth_bypass() -> None:
    profile = load_profile("litellm")
    with gateway("vulnerable") as target:
        result = run_gate(profile, target)
    flagged = {f.probe_id for f in result.findings}
    assert {"GATE001", "GATE002", "GATE003", "GATE004", "GATE006", "GATE007"} <= flagged
    gate001 = next(f for f in result.findings if f.probe_id == "GATE001")
    assert gate001.severity.value == "critical"
    assert gate001.cve == "CVE-2026-59822"
    assert gate001.remediation
    assert "POST /mcp -> 200" in gate001.evidence


def test_mcp_session_id_is_carried_between_steps() -> None:
    profile = load_profile("litellm")
    with gateway("vulnerable") as target:
        run_gate(profile, target)
    sessions = [entry["session"] for entry in SEEN]
    assert "test-session-1" in sessions


def test_method_preserving_redirect_is_followed() -> None:
    profile = load_profile("litellm")
    with gateway("redirect") as target:
        result = run_gate(profile, target)
    gate001 = next(f for f in result.findings if f.probe_id == "GATE001")
    assert "-> 200" in gate001.evidence
    assert all(note.status != 307 for note in result.notes)


def test_server_error_instead_of_denial_is_a_low_finding() -> None:
    profile = load_profile("litellm")
    with gateway("erroring") as target:
        result = run_gate(profile, target)
    gate001 = next(f for f in result.findings if f.probe_id == "GATE001")
    assert gate001.severity.value == "low"
    assert "errored instead of denying" in gate001.title
    assert "500" in gate001.evidence


def test_missing_routes_are_inconclusive_not_findings() -> None:
    profile = load_profile("litellm")
    with gateway("missing") as target:
        result = run_gate(profile, target)
    assert result.findings == []
    assert len(result.notes) == result.probes_run


def test_refuses_non_loopback_without_allow_host() -> None:
    profile = load_profile("litellm")
    with pytest.raises(GateError, match="allow-host"):
        run_gate(profile, "http://gateway.example.com")


def test_cli_vulnerable_exits_one_and_prints_findings() -> None:
    with gateway("vulnerable") as target:
        result = runner.invoke(app, ["gate", target, "--fail-on", "high"])
    assert result.exit_code == 1, result.output
    assert "GATE001" in result.output
    assert "Fix:" in result.output


def test_cli_patched_exits_zero() -> None:
    with gateway("patched") as target:
        result = runner.invoke(app, ["gate", target, "--fail-on", "low"])
    assert result.exit_code == 0, result.output
    assert "No findings" in result.output


def test_cli_json_output_is_machine_readable() -> None:
    with gateway("vulnerable") as target:
        result = runner.invoke(app, ["gate", target, "--json", "--fail-on", "none"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["tool"] == "mcplint gate"
    assert payload["summary"]["total"] > 0
    assert payload["findings"][0]["probeId"].startswith("GATE")


def test_cli_refuses_remote_target_with_exit_code_two() -> None:
    result = runner.invoke(app, ["gate", "http://gateway.example.com"])
    assert result.exit_code == 2
    assert "allow-host" in result.output


# --- authenticated checks (mcplint gate --auth) ---


def _write_expectations(tmp_path, **overrides):
    data = {
        "target": "http://127.0.0.1:1",
        "key": "env/MCPLINT_TEST_KEY",
        "expect_tools": ["confluence.search", "confluence.get_page"],
        "forbidden_tools": ["*delete*"],
        "forbidden_servers": ["github"],
    }
    data.update(overrides)
    path = tmp_path / "auth.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_auth_mode_clean_key(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(_write_expectations(tmp_path))
    with gateway("auth") as target:
        result = run_auth_gate(expectations, target)
    assert result.findings == [], [f.to_dict() for f in result.findings]
    assert result.inventory == TOOLS


def test_auth_mode_flags_forbidden_and_extra_tools(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(_write_expectations(tmp_path))
    with gateway("overexposed") as target:
        result = run_auth_gate(expectations, target)
    flagged = {f.probe_id: f for f in result.findings}
    assert "AUTH001" in flagged and flagged["AUTH001"].severity.value == "high"
    assert "AUTH002" in flagged and flagged["AUTH002"].severity.value == "medium"


def test_auth_mode_flags_scope_leak(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(_write_expectations(tmp_path))
    with gateway("leaky_scope") as target:
        result = run_auth_gate(expectations, target)
    flagged = {f.probe_id for f in result.findings}
    assert "AUTH003" in flagged


def test_auth_mode_read_probe_leak_is_redacted(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(
        _write_expectations(
            tmp_path,
            read_probe={
                "tool": "confluence.get_page",
                "args": {"page_id": "00000000"},
                "expect": "deny",
            },
        )
    )
    with gateway("leaky_read") as target:
        result = run_auth_gate(expectations, target)
    auth004 = next(f for f in result.findings if f.probe_id == "AUTH004")
    assert auth004.severity.value == "critical"
    assert "redacted-secret" not in auth004.evidence


def test_auth_mode_read_probe_denied_is_clean(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    expectations = load_auth_expectations(
        _write_expectations(
            tmp_path,
            read_probe={"tool": "confluence.get_page", "args": {}, "expect": "deny"},
        )
    )
    with gateway("auth") as target:
        result = run_auth_gate(expectations, target)
    assert all(f.probe_id != "AUTH004" for f in result.findings)


def test_auth_mode_requires_key_in_environment(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("MCPLINT_TEST_KEY", raising=False)
    expectations = load_auth_expectations(_write_expectations(tmp_path))
    with gateway("auth") as target, pytest.raises(GateError, match="MCPLINT_TEST_KEY"):
        run_auth_gate(expectations, target)


def test_auth_expectations_reject_literal_key(tmp_path) -> None:
    path = _write_expectations(tmp_path, key="sk-literal-key")
    with pytest.raises(GateError, match="env/"):
        load_auth_expectations(path)


def test_auth_cli_clean_and_key_never_printed(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MCPLINT_TEST_KEY", KEY)
    path = _write_expectations(tmp_path)
    with gateway("auth") as target:
        result = runner.invoke(app, ["gate", target, "--auth", str(path), "--json"])
    assert result.exit_code == 0, result.output
    assert "No findings" in result.output or '"total": 0' in result.output
    assert KEY not in result.output
    assert "confluence.search" in result.output
