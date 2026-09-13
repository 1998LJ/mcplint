"""SARIF 2.1.0 output for GitHub code scanning and other consumers."""

from __future__ import annotations

from typing import Any

from .. import __version__
from ..models import Finding, Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_sarif(findings: list[Finding]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        if finding.rule_id not in rules:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "properties": {"owasp": finding.owasp or ""},
            }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _LEVEL[finding.severity],
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file.replace("\\", "/"),
                            },
                            "region": {"startLine": max(1, finding.line)},
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity.value,
                    "owasp": finding.owasp or "",
                    "server": finding.server or "",
                },
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcplint",
                        "version": __version__,
                        "informationUri": "https://github.com/dtduc-git/mcplint",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
