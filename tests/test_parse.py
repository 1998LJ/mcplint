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


def test_nested_configs_are_discovered(tmp_path: Path) -> None:
    from mcplint.discovery import discover

    nested = tmp_path / "packages" / "api"
    nested.mkdir(parents=True)
    (nested / ".mcp.json").write_text(
        '{"mcpServers": {"demo": {"command": "npx", "args": ["demo@1.0.0"]}}}',
        encoding="utf-8",
    )
    cursor = tmp_path / "apps" / "web" / ".cursor"
    cursor.mkdir(parents=True)
    (cursor / "mcp.json").write_text("{}", encoding="utf-8")
    skipped = tmp_path / "node_modules" / "pkg"
    skipped.mkdir(parents=True)
    (skipped / ".mcp.json").write_text("{}", encoding="utf-8")

    configs, _ = discover([tmp_path])
    names = {path.name for path in configs}
    assert ".mcp.json" in names
    assert "mcp.json" in names
    assert all("node_modules" not in str(path) for path in configs)


def test_claude_json_user_scope_discovery(tmp_path: Path, monkeypatch) -> None:
    from mcplint.discovery import discover

    home = tmp_path / "home"
    home.mkdir()
    claude_json = home / ".claude.json"
    claude_json.write_text(
        """
        {
          "numCachedChunks": 12,
          "mcpServers": {
            "sqlite": { "command": "uvx", "args": ["mcp-server-sqlite"] }
          }
        }
        """,
        encoding="utf-8",
    )

    monkeypatch.setenv("HOME", str(home))
    configs, _ = discover([], include_home=True)
    assert any(c.name == ".claude.json" for c in configs)

    parsed = parse_config_file(claude_json)
    assert parsed is not None
    assert parsed.client == "claude-code"
    assert len(parsed.servers) == 1
    assert parsed.servers[0].name == "sqlite"
    assert parsed.servers[0].command == ["uvx", "mcp-server-sqlite"]


def test_claude_json_malformed_skipped(tmp_path: Path, monkeypatch) -> None:
    from mcplint.discovery import discover

    home = tmp_path / "home"
    home.mkdir()
    claude_json = home / ".claude.json"
    claude_json.write_text("{invalid json", encoding="utf-8")

    monkeypatch.setenv("HOME", str(home))
    configs, _ = discover([], include_home=True)
    assert any(c.name == ".claude.json" for c in configs)

    # Parsing should return None safely without crashing
    assert parse_config_file(claude_json) is None


def test_claude_json_oversized_skipped(tmp_path: Path, monkeypatch) -> None:
    from mcplint.discovery import discover
    from mcplint.parse import MAX_CONFIG_BYTES

    home = tmp_path / "home"
    home.mkdir()
    claude_json = home / ".claude.json"

    # Write a file exceeding MAX_CONFIG_BYTES
    claude_json.write_bytes(b" " * (MAX_CONFIG_BYTES + 1))

    monkeypatch.setenv("HOME", str(home))
    configs, _ = discover([], include_home=True)
    assert any(c.name == ".claude.json" for c in configs)

    # Parsing oversized config should safely return None without reading/crashing
    assert parse_config_file(claude_json) is None

