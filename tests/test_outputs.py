from pathlib import Path

from mcplint.aibom import build_aibom
from mcplint.parse import parse_config_file
from mcplint.report.sarif import to_sarif
from mcplint.rules import load_rules
from mcplint.scanner import scan

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_sarif_shape_matches_findings() -> None:
    result = scan([FIXTURES / "vulnerable-repo"], load_rules())
    sarif = to_sarif(result.findings)
    assert sarif["version"] == "2.1.0"
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "mcplint"
    assert len(sarif["runs"][0]["results"]) == len(result.findings)
    levels = {entry["level"] for entry in sarif["runs"][0]["results"]}
    assert levels <= {"error", "warning", "note"}
    rule_ids = {rule["id"] for rule in driver["rules"]}
    assert "MCP001" in rule_ids


def test_aibom_lists_servers_with_purls() -> None:
    config = parse_config_file(FIXTURES / "vulnerable-repo/.mcp.json")
    assert config is not None
    bom = build_aibom([config], FIXTURES / "vulnerable-repo")
    assert bom["bomFormat"] == "CycloneDX"
    names = {component["name"] for component in bom["components"]}
    assert {"github", "files", "remote-legacy"} <= names
    github = next(c for c in bom["components"] if c["name"] == "github")
    assert github["purl"].startswith("pkg:npm/")
    assert github["type"] == "library"
    remote = next(c for c in bom["components"] if c["name"] == "remote-legacy")
    assert remote["type"] == "application"
    assert "purl" not in remote
