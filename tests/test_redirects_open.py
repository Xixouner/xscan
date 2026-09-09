from xscan.modules.redirects_open import _suspect_params, candidate_links
import httpx


def test_suspect_params_detected():
    link = httpx.URL("https://t.test/login?next=/dashboard&lang=fr")
    assert _suspect_params(link) == ["next"]


def test_no_suspect_params():
    assert _suspect_params(httpx.URL("https://t.test/page?lang=fr&id=3")) == []


def test_candidate_links_rewrites_probe_param():
    html = '<a href="/out?url=https://partenaire.t/"><img src="/x.png"></a>'
    candidates = candidate_links(html, "https://t.test/")
    assert len(candidates) == 1
    assert "xscan-open-redirect.invalid" in candidates[0]
    assert "url=" in candidates[0]


def test_external_links_skipped():
    html = '<a href="https://tiers.test/?next=/x">tiers</a>'
    assert candidate_links(html, "https://t.test/") == []
