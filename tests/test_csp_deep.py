from xscan.modules.csp_deep import analyze
from xscan.models import Severity


def test_unsafe_inline_is_medium():
    findings = analyze("default-src 'self'; script-src 'self' 'unsafe-inline'")
    assert findings[0].id == "XSCAN-CSP-001"
    assert findings[0].severity is Severity.MEDIUM


def test_unsafe_eval_is_low():
    findings = analyze("script-src 'self' 'unsafe-eval'")
    assert any(finding.id == "XSCAN-CSP-002" and finding.severity is Severity.LOW for finding in findings)


def test_wildcard_script_source_is_medium():
    findings = analyze("script-src * 'unsafe-inline'")
    assert any(finding.id == "XSCAN-CSP-003" for finding in findings)


def test_strong_csp_no_finding():
    assert analyze("default-src 'self'; script-src 'self' 'nonce-abc'") == []


def test_absent_csp_not_this_module():
    assert analyze("") == []
