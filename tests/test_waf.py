from xscan.modules.waf import detect


def _headers(*extra: tuple[str, str]) -> object:
    import httpx
    return httpx.Headers(dict(extra))


def test_cloudflare_via_cf_ray():
    findings = detect(_headers(("cf-ray", "abc")), [])
    assert findings[0].title.endswith("Cloudflare")
    assert findings[0].severity.value == "info"


def test_akamai_via_cookie():
    findings = detect(_headers(), ["ak_bmsc=xyz; Path=/"])
    assert any("Akamai" in finding.title for finding in findings)


def test_no_waf_no_finding():
    assert detect(_headers(("server", "nginx")), []) == []
