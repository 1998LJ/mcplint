import json
from pathlib import Path

from mcplint.rules import load_rules
from mcplint.scanner import scan

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

EXPECTED_VULNERABLE = {
    "MCP001",  # secrets (ghp_, URL creds, generic token env)
    "MCP003",  # unpinned npm/pypi packages
    "MCP004",  # typosquat: mcp-server-postgress
    "MCP005",  # http:// remote endpoint
    "MCP006",  # remote without auth
    "MCP007",  # filesystem server scoped to /
    "MCP008",  # bash shell server
    "MCP009",  # injection markers in AGENTS.md / SKILL.md
    "MCP010",  # zero-width space in SKILL.md
    "MCP011",  # "files" defined in two configs
}


def test_vulnerable_fixture_triggers_expected_rules() -> None:
    result = scan([FIXTURES / "vulnerable-repo"], load_rules())
    ids = {finding.rule_id for finding in result.findings}
    missing = EXPECTED_VULNERABLE - ids
    assert not missing, f"missing expected findings: {sorted(missing)}"


def test_clean_fixture_has_no_findings() -> None:
    result = scan([FIXTURES / "clean-repo"], load_rules())
    assert result.findings == [], [f.to_dict() for f in result.findings]


def test_secrets_are_attributed_to_server_and_line() -> None:
    result = scan([FIXTURES / "vulnerable-repo"], load_rules())
    secrets = [f for f in result.findings if f.rule_id == "MCP001"]
    by_server = {f.server for f in secrets}
    assert "github" in by_server
    github = next(f for f in secrets if f.server == "github")
    assert github.line > 1
    assert "GitHub token" in github.message


def test_typosquat_flags_postgress() -> None:
    result = scan([FIXTURES / "vulnerable-repo"], load_rules())
    typos = [f for f in result.findings if f.rule_id == "MCP004"]
    assert any("postgress" in f.message for f in typos)


def test_pinned_package_is_not_flagged() -> None:
    result = scan([FIXTURES / "vulnerable-repo"], load_rules())
    unpinned = [f for f in result.findings if f.rule_id == "MCP003"]
    assert all("memory-pinned" != f.server for f in unpinned)


def test_typosquat_ignores_separator_and_scope_variants(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "a": {"command": "npx", "args": ["playwright-mcp@1.0.0"]},
                    "b": {"command": "npx", "args": ["mcp-server-postgresql@1.0.0"]},
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    assert not [f for f in result.findings if f.rule_id == "MCP004"]


def test_private_http_host_ranks_lower_than_public(tmp_path: Path) -> None:
    path = tmp_path / ".mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "internal": {"url": "http://agent-gateway:8787/mcp"},
                    "public": {"url": "http://mcp.example.com/mcp"},
                }
            }
        ),
        encoding="utf-8",
    )
    result = scan([tmp_path], load_rules())
    http = [f for f in result.findings if f.rule_id == "MCP005"]
    internal = next(f for f in http if "agent-gateway" in f.message)
    public = next(f for f in http if "mcp.example.com" in f.message)
    assert internal.severity.value == "low"
    assert public.severity.value == "high"
