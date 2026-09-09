from __future__ import annotations

import json
from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from xscan import __version__
from xscan.models import ScanResult, Severity

_SEV_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _severity_style(severity: str) -> str:
    return _SEV_STYLES.get(severity, "white")


def _module_table(module_result) -> Table:
    count = len(module_result.findings)
    table = Table(title=f"module : {module_result.module} — {count} constat(s)", title_justify="left", expand=True)
    for column in ("ID", "Sévérité", "Constat", "Preuve / détail"):
        table.add_column(column, overflow="fold")
    for finding in module_result.findings:
        table.add_row(
            str(finding.id),
            f"[{_severity_style(finding.severity.value)}]{finding.severity.value}[/]",
            str(finding.title),
            str(finding.evidence or "—")[:90],
        )
    if module_result.error:
        table.add_row("—", "[bold red]error[/]", f"Module en échec : {module_result.error}", "—")
    if not module_result.findings and not module_result.error:
        table.add_row("—", "[green]ok[/]", "Aucun constat", "—")
    return table


def render_rich(result: ScanResult, console: Console) -> None:
    score = result.score()
    style = "green" if score >= 85 else "yellow" if score >= 60 else "red"
    header = f"[bold]{result.target}[/]\n[bold {style}]score : {score}/100[/] — {result.duration_s}s"
    console.print(Panel(header, title="xscan", expand=False))
    for module_result in result.results:
        console.print(_module_table(module_result))


def result_to_dict(result: ScanResult) -> dict:
    counts = Counter(finding.severity.value for finding in result.findings())
    return {
        "tool": "xscan",
        "version": __version__,
        "target": result.target,
        "duration_s": result.duration_s,
        "score": result.score(),
        "summary": {severity.value: counts.get(severity.value, 0) for severity in Severity},
        "modules": [
            {
                "name": module_result.module,
                "error": module_result.error,
                "findings": [
                    {
                        "id": finding.id,
                        "severity": finding.severity.value,
                        "title": finding.title,
                        "evidence": finding.evidence,
                        "remediation": finding.remediation,
                    }
                    for finding in module_result.findings
                ],
            }
            for module_result in result.results
        ],
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(result_to_dict(result), indent=2, ensure_ascii=False)
