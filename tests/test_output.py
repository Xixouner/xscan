from xscan.models import Finding, ModuleResult, ScanResult, Severity
from xscan.output import to_markdown


def test_markdown_contains_target_score_and_findings():
    result = ScanResult(
        target="https://t.test",
        results=[ModuleResult("dns", [Finding("XSCAN-DNS-001", "dns", Severity.MEDIUM, "Aucun SPF", "TXT absent", "Publier un SPF")])],
    )
    markdown = to_markdown(result)
    assert "https://t.test" in markdown
    assert "55/100" in markdown
    assert "XSCAN-DNS-001" in markdown
    assert "| medium | dns |" in markdown


def test_markdown_escapes_pipes_in_cells():
    finding = Finding("X-1", "headers", Severity.LOW, "Cookie flags", "a|b|c", "fix")
    markdown = to_markdown(ScanResult(target="https://t.test", results=[ModuleResult("headers", [finding])]))
    assert "a\\|b\\|c" in markdown


def test_markdown_empty_results_still_valid():
    markdown = to_markdown(ScanResult(target="https://t.test"))
    assert "| Sévérité | Module |" in markdown
