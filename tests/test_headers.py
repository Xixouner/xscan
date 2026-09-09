import httpx

from xscan.models import Severity
from xscan.modules import headers


def _resp(headers_dict: dict) -> httpx.Response:
    return httpx.Response(200, headers=headers_dict, request=httpx.Request("GET", "https://cible.test/"))


def test_absent_headers_reported():
    findings = headers.evaluate(_resp({}))
    ids = {finding.id for finding in findings}
    assert "XSCAN-HEADERS-001" in ids
    assert "XSCAN-HEADERS-002" in ids
    assert "XSCAN-HEADERS-003" in ids


def test_strong_headers_not_flagged():
    response = _resp({
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=63072000; includeSubDomains",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
    })
    ids = {finding.id for finding in headers.evaluate(response)}
    assert not {"XSCAN-HEADERS-001", "XSCAN-HEADERS-002", "XSCAN-HEADERS-003"} & ids


def test_cookie_without_flags_flagged():
    findings = headers.evaluate(_resp({"set-cookie": "sid=abc; Path=/"}))
    assert any("sid" in finding.title for finding in findings)


def test_cors_wildcard_is_medium():
    findings = headers.evaluate(_resp({"access-control-allow-origin": "*"}))
    assert any(finding.id == "XSCAN-HEADERS-009" and finding.severity is Severity.MEDIUM for finding in findings)


def test_short_hsts_max_age_flagged():
    findings = headers.evaluate(_resp({"strict-transport-security": "max-age=3600"}))
    assert any(finding.id == "XSCAN-HEADERS-007" for finding in findings)
