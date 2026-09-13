from pathlib import Path

from mcplint.parse import parse_config_file, strip_jsonc

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_parse_claude_json() -> None:
    config = parse_config_file(FIXTURES / "vulnerable-repo/.mcp.json")
    assert config is not None
    names = {server.name for server in config.servers}
    assert {"files", "github", "remote-legacy", "shell"} <= names
    remote = next(s for s in config.servers if s.name == "remote-legacy")
    assert remote.transport == "http"
    assert remote.url == "http://mcp.example.com/sse"
    files = next(s for s in config.servers if s.name == "files")
    assert files.transport == "stdio"
    assert files.env["LOG_LEVEL"] == "debug"


def test_parse_codex_toml() -> None:
    config = parse_config_file(FIXTURES / "vulnerable-repo/.codex/config.toml")
    assert config is not None
    assert len(config.servers) == 1
    server = config.servers[0]
    assert server.name == "internal-search"
    assert server.env["INTERNAL_SEARCH_TOKEN"].startswith("tok_live")


def test_parse_opencode_json() -> None:
    config = parse_config_file(FIXTURES / "vulnerable-repo/opencode.json")
    assert config is not None
    assert config.servers[0].command == ["uvx", "some-mcp-tool"]
    assert config.servers[0].env["MCP_API_KEY"]


def test_parse_vscode_servers_key(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text(
        """
        {
          // VS Code style
          "servers": {
            "demo": { "type": "stdio", "command": "npx", "args": ["demo@1.0.0"] },
          }
        }
        """,
        encoding="utf-8",
    )
    config = parse_config_file(path)
    assert config is not None
    assert config.servers[0].name == "demo"


def test_strip_jsonc_keeps_strings() -> None:
    text = '{"a": "http://x // not a comment", /* c */ "b": 1,}'
    assert strip_jsonc(text) == '{"a": "http://x // not a comment",  "b": 1}'


def test_parse_rejects_non_mcp_json(tmp_path: Path) -> None:
    path = tmp_path / "package.json"
    path.write_text('{"name": "demo", "version": "1.0.0"}', encoding="utf-8")
    assert parse_config_file(path) is None
