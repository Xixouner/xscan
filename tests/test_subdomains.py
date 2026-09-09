import json

from xscan.modules import subdomains


def test_parse_crt_dedupes_and_strips_wildcards():
    payload = json.dumps([
        {"name_value": "*.xixouner.com\nxixouner.com"},
        {"name_value": "www.xixouner.com"},
        {"name_value": "www.xixouner.com"},
        {"name_value": "other.example.org"},
    ])
    assert subdomains._parse_crt(payload, "xixouner.com") == {"www.xixouner.com"}


def test_parse_crt_invalid_json_returns_empty():
    assert subdomains._parse_crt("pas du json", "d.com") == set()


def test_sensitive_subdomains_flagged():
    subs = ["www.xixouner.com", "staging.xixouner.com", "api.xixouner.com", "blog.xixouner.com"]
    flagged = subdomains._sensitive_subdomains(subs)
    assert "staging.xixouner.com" in flagged
    assert "api.xixouner.com" in flagged
    assert "www.xixouner.com" not in flagged
    assert "blog.xixouner.com" not in flagged
