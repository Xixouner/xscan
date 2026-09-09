from xscan.modules.sri import analyze


def _page(*scripts: str) -> str:
    return "<html><body>" + "".join(scripts) + "</body></html>"


def test_external_script_without_sri_flagged():
    html = _page('<script src="https://cdn.t/lib.js"></script>')
    findings = analyze(html, "https://t.test/")
    assert len(findings) == 1
    assert findings[0].id == "XSCAN-SRI-001"
    assert "cdn.t" in findings[0].evidence


def test_external_script_with_integrity_ok():
    html = _page('<script src="https://cdn.t/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>')
    assert analyze(html, "https://t.test/") == []


def test_same_origin_script_not_flagged():
    html = _page('<script src="/_next/static/chunk.js"></script>')
    assert analyze(html, "https://t.test/") == []


def test_mixed_counts_only_unprotected():
    html = _page(
        '<script src="https://a.t/x.js"></script>'
        '<script src="https://b.t/y.js" integrity="sha384-abc"></script>'
    )
    findings = analyze(html, "https://t.test/")
    assert len(findings) == 1
    assert "https://a.t/x.js" in findings[0].evidence
