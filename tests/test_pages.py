from xscan.modules.pages import _internal_links, _page_findings
from xscan.models import Severity


def test_internal_links_same_host_only():
    html = '<a href="/a-propos">A</a><a href="https://tiers.test/x">B</a><a href="/img.png">C</a>'
    links = _internal_links("https://t.test/", html)
    assert links == ["https://t.test/a-propos"]


def test_no_fragment_duplicates():
    html = '<a href="/a">A</a><a href="/a">A2</a>'
    assert _internal_links("https://t.test/", html) == ["https://t.test/a"]


def test_mixed_content_flagged_on_https():
    html = '<img src="http://t.test/logo.png">'
    findings = _page_findings("https://t.test/", html)
    assert findings[0].id == "XSCAN-PAGES-001"
    assert findings[0].severity is Severity.MEDIUM


def test_mixed_content_not_flagged_on_http():
    assert _page_findings("http://t.test/", '<img src="http://t.test/logo.png">') == []


def test_python_traceback_is_high():
    html = "Traceback (most recent call last):<br>File /app/main.py"
    findings = _page_findings("https://t.test/", html)
    assert any(finding.id == "XSCAN-PAGES-002" and finding.severity is Severity.HIGH for finding in findings)


def test_clean_page_no_finding():
    assert _page_findings("https://t.test/", "<p>page tout à fait saine</p>") == []
