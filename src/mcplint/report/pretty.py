"""Human-readable terminal report."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..models import ScanResult, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render(result: ScanResult, console: Console) -> None:
    console.print(
        f"Scanned [bold]{len(result.configs)}[/bold] config(s) and "
        f"[bold]{len(result.instructions)}[/bold] instruction file(s)."
    )
    if not result.findings:
        console.print("[green]No findings.[/green]")
        return

    table = Table(header_style="bold", pad_edge=False)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Location", no_wrap=True)
    table.add_column("Server", no_wrap=True)
    table.add_column("Detail", overflow="fold")
    for finding in result.findings:
        table.add_row(
            Text(finding.severity.value.upper(), style=_SEV_STYLE[finding.severity]),
            Text(finding.rule_id),
            Text(f"{finding.file}:{finding.line}"),
            Text(finding.server or "-"),
            Text(finding.message),
        )
    console.print(table)

    counts = result.counts()
    summary = ", ".join(f"{count} {name}" for name, count in counts.items())
    console.print(f"[bold]{len(result.findings)}[/bold] finding(s): {summary}")
