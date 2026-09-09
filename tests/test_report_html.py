import json

from xscan import __version__
from xscan.models import Finding, ModuleResult, ScanResult, Severity
from xscan.report_html import render_html


def _result(findings: list[Finding]) -> ScanResult:
    return ScanResult(target="https://t.test", results=[ModuleResult("headers", findings)])


def test_report_contains_target_score_and_finding():
    finding = Finding("XSCAN-HEADERS-001", "headers", Severity.MEDIUM, "CSP absente", "en-tête absent", "Ajouter CSP")
    out = render_html(_result([finding]))
    assert "https://t.test" in out
    assert f"xscan {__version__}" in out
    assert "XSCAN-HEADERS-001" in out
    assert "CSP absente" in out


def test_report_escapes_evidence_against_html_injection():
    malicious = '<script>alert(1)</script>'
    finding = Finding("X-1", "headers", Severity.LOW, "Preuve hostile", malicious, "—")
    out = render_html(_result([finding]))
    assert malicious not in out
    assert "&lt;script&gt;" in out


def test_report_scores_and_badges_present():
    finding = Finding("X-2", "headers", Severity.CRITICAL, "Clé exposée", "AKIA…", "Révoquer")
    out = render_html(_result([finding]))
    assert "score 70/100" in out
    assert "critical: 1" in out
    assert "#b91c1c" in out  # couleur critical
