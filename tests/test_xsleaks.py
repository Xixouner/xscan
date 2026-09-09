import httpx

from xscan.modules.xsleaks import analyze


def _headers(*names: str) -> httpx.Headers:
    return httpx.Headers({name: "x" for name in names})


def test_no_policies_all_flagged():
    findings = analyze(_headers())
    ids = {finding.id for finding in findings}
    assert {"XSCAN-XSL-001", "XSCAN-XSL-002", "XSCAN-XSL-003"} <= ids


def test_coop_present_silences_001():
    findings = analyze(_headers("cross-origin-opener-policy"))
    assert "XSCAN-XSL-001" not in {finding.id for finding in findings}
