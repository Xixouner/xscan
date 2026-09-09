import httpx

from xscan.modules import fingerprint


def test_nextjs_and_wordpress_detected():
    html = '<script src="/_next/static/chunk.js"></script><div id="__NEXT_DATA__"></div> /wp-content/themes/'
    titles = {finding.title for finding in fingerprint.detect(httpx.Headers({"server": "nginx"}), html)}
    assert any("Next.js" in title for title in titles)
    assert any("WordPress" in title for title in titles)
    assert any("Nginx" in title for title in titles)


def test_generator_meta_detected():
    html = '<meta name="generator" content="WordPress 6.5">'
    titles = {finding.title for finding in fingerprint.detect(httpx.Headers(), html)}
    assert any("WordPress 6.5" in title for title in titles)


def test_vercel_via_header_presence():
    findings = fingerprint.detect(httpx.Headers({"x-vercel-id": "cdg1::abc"}), "<html></html>")
    assert any("Vercel" in finding.title for finding in findings)


def test_no_fingerprint_on_empty_page():
    assert fingerprint.detect(httpx.Headers(), "<html></html>") == []
