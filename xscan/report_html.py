from __future__ import annotations

import html
from collections import Counter
from datetime import UTC, datetime

from xscan import __version__
from xscan.models import ScanResult

_SEV_COLORS = {
    "critical": "#b91c1c",
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#0891b2",
    "info": "#6b7280",
}


def _score_color(score: int) -> str:
    if score >= 85:
        return "#16a34a"
    if score >= 60:
        return "#d97706"
    return "#dc2626"


def render_html(result: ScanResult) -> str:
    """Rapport HTML autonome (CSS inline, échappé) pour envoi à un client."""
    findings = result.findings()
    counts = Counter(finding.severity.value for finding in findings)
    score = result.score()
    generated = datetime.now(tz=UTC).strftime("%d/%m/%Y %H:%M UTC")
    sections = "\n".join(_module_section(module_result) for module_result in result.results)
    return f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>xscan — {html.escape(result.target)}</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #111827; }}
.badge {{ display: inline-block; padding: 0.15rem 0.6rem; border-radius: 9999px; color: #fff; font-weight: 600; font-size: 0.8rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #e5e7eb; padding: 0.5rem 0.6rem; text-align: left; vertical-align: top; font-size: 0.9rem; }}
th {{ background: #f3f4f6; }}
pre {{ white-space: pre-wrap; word-break: break-all; margin: 0; font-size: 0.8rem; color: #374151; }}
.small {{ color: #6b7280; font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>Rapport xscan <span class="badge" style="background:{_score_color(score)}">score {score}/100</span></h1>
<p>Cible : <strong>{html.escape(result.target)}</strong><br>
Durée : {result.duration_s}s — Généré le {generated} par xscan {__version__}</p>
<p>{' '.join(f'<span class="badge" style="background:{_SEV_COLORS[sev]}">{sev}: {counts.get(sev, 0)}</span>'
             for sev in ("critical", "high", "medium", "low", "info"))}</p>
{sections}
<p class="small">Avertissement : ce rapport ne couvre que les modules exécutés au moment du scan.
N'analyser que des cibles autorisées.</p>
</body>
</html>"""


def _module_section(module_result) -> str:
    title = f"<h2>module : {html.escape(module_result.module)}</h2>"
    if module_result.error:
        return f"{title}<p>Module en échec : {html.escape(module_result.error)}</p>"
    if not module_result.findings:
        return f"{title}<p class=\"small\">Aucun constat.</p>"
    rows = "\n".join(_finding_row(finding) for finding in module_result.findings)
    return f"""{title}
<table><tr><th>ID</th><th>Sévérité</th><th>Constat</th><th>Preuve / détail</th><th>Remédiation</th></tr>
{rows}
</table>"""


def _finding_row(finding) -> str:
    sev = finding.severity.value
    return (f"<tr><td>{html.escape(finding.id)}</td>"
            f"<td><span class=\"badge\" style=\"background:{_SEV_COLORS[sev]}\">{sev}</span></td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td><pre>{html.escape(finding.evidence or '—')}</pre></td>"
            f"<td>{html.escape(finding.remediation or '—')}</td></tr>")
