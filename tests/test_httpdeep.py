from xscan.modules.httpdeep import allow_findings, reflection_findings
from xscan.models import Severity


def test_risky_methods_flagged():
    findings = allow_findings("GET, POST, PUT, TRACE")
    assert findings[0].id == "XSCAN-HTTP-002"
    assert "PUT" in findings[0].title and "TRACE" in findings[0].title


def test_safe_methods_not_flagged():
    assert allow_findings("GET, POST, HEAD") == []


def test_empty_allow_not_flagged():
    assert allow_findings("") == []


def test_host_reflection_in_location_flagged():
    findings = reflection_findings("https://xscan-probe.invalid/redirect", "", "xscan-probe.invalid")
    assert findings[0].id == "XSCAN-HTTP-003"
    assert findings[0].severity is Severity.MEDIUM


def test_host_reflection_in_body_flagged():
    assert reflection_findings("", "<a href='https://xscan-probe.invalid'>x</a>", "xscan-probe.invalid")


def test_no_reflection_no_finding():
    assert reflection_findings("https://t.test/login", "page normale", "xscan-probe.invalid") == []
