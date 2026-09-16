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


def test_cline_linux_discovery_and_parse(tmp_path: Path, monkeypatch) -> None:
    from mcplint.discovery import discover

    home = tmp_path / "home"
    cline_dir = (
        home
        / ".config"
        / "Code"
        / "User"
        / "globalStorage"
        / "saoudrizwan.claude-dev"
        / "settings"
    )
    cline_dir.mkdir(parents=True)
    settings = cline_dir / "cline_mcp_settings.json"
    settings.write_text(
        """
        {
          "mcpServers": {
            "weather": {
              "command": "node",
              "args": ["build/index.js"],
              "env": {
                "API_KEY": "secret"
              }
            }
          }
        }
        """,
        encoding="utf-8",
    )

    monkeypatch.setenv("HOME", str(home))
    configs, _ = discover([], include_home=True)
    assert any(c.name == "cline_mcp_settings.json" for c in configs)

    parsed = parse_config_file(settings)
    assert parsed is not None
    assert parsed.client == "cline"
    assert len(parsed.servers) == 1
    assert parsed.servers[0].name == "weather"
    assert parsed.servers[0].command == ["node", "build/index.js"]
    assert parsed.servers[0].env["API_KEY"] == "secret"


def test_cline_macos_discovery_with_spaces(tmp_path: Path, monkeypatch) -> None:
    from mcplint.discovery import discover

    home = tmp_path / "home"
    cline_dir = (
        home
        / "Library"
        / "Application Support"
        / "Code"
        / "User"
        / "globalStorage"
        / "saoudrizwan.claude-dev"
        / "settings"
    )
    cline_dir.mkdir(parents=True)
    settings = cline_dir / "cline_mcp_settings.json"
    settings.write_text(
        """
        {
          "mcpServers": {
            "fetch": {
              "command": "uvx",
              "args": ["mcp-server-fetch"]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    monkeypatch.setenv("HOME", str(home))
    configs, _ = discover([], include_home=True)
    assert any(
        "Application Support" in str(c) and c.name == "cline_mcp_settings.json"
        for c in configs
    )

    parsed = parse_config_file(settings)
    assert parsed is not None
    assert parsed.client == "cline"
    assert parsed.servers[0].name == "fetch"

