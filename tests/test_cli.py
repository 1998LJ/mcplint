import json
from pathlib import Path

from typer.testing import CliRunner

from mcplint.cli import app

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
runner = CliRunner()


def test_scan_clean_repo_exits_zero() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "clean-repo"), "--fail-on", "low"])
    assert result.exit_code == 0, result.output
    assert "No findings" in result.output


def test_scan_vulnerable_repo_exits_one() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "vulnerable-repo")])
    assert result.exit_code == 1, result.output


def test_scan_fail_on_none_never_fails() -> None:
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "vulnerable-repo"), "--fail-on", "none"]
    )
    assert result.exit_code == 0, result.output


def test_scan_json_output_is_machine_readable() -> None:
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "vulnerable-repo"), "--json", "--fail-on", "none"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["summary"]["total"] > 0
    assert payload["findings"][0]["ruleId"].startswith("MCP")


def test_rules_list_contains_builtins() -> None:
    result = runner.invoke(app, ["rules", "list"], env={"COLUMNS": "300"})
    assert result.exit_code == 0, result.output
    assert "MCP001" in result.output
    assert "MCP013" in result.output


def test_rules_explain_unknown_exits_two() -> None:
    result = runner.invoke(app, ["rules", "explain", "NOPE"])
    assert result.exit_code == 2


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "mcplint" in result.output
