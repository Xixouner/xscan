from xscan.modules.xss_probe import candidate_links, reflection_findings
import httpx

MARKER = 'xs7q"\'>(mrk)'


def test_candidate_links_injects_marker():
    html = '<a href="/recherche?q=abc">A</a><a href="/page">B</a>'
    candidates = candidate_links(html, "https://t.test/")
    assert len(candidates) == 1
    # le marqueur est percent-encodé dans l'URL, décodé par le serveur à la réception
    assert httpx.URL(candidates[0]).params["q"] == MARKER


def test_reflection_brut_flagged():
    body = f'<div>Vous avez cherché : {MARKER}</div>'
    findings = reflection_findings(body, "https://t.test/?q=x")
    assert findings[0].id == "XSCAN-XSS-001"
    assert findings[0].severity.value == "medium"


def test_reflection_html_escaped_not_flagged():
    escaped = "xs7q&quot;&#x27;&gt;(mrk)"
    assert reflection_findings(f"<div>{escaped}</div>", "https://t.test/?q=x") == []


def test_clean_body_not_flagged():
    assert reflection_findings("<p>page normale</p>", "https://t.test/?q=x") == []
