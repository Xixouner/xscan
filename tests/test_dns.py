from xscan.modules.dns import dmarc_findings, spf_findings
from xscan.models import Severity


def test_spf_absent_is_medium():
    findings = spf_findings([])
    assert findings[0].id == "XSCAN-DNS-001"
    assert findings[0].severity is Severity.MEDIUM


def test_spf_plusall_is_high():
    findings = spf_findings(["v=spf1 ip4:1.2.3.4 +all"])
    assert findings[0].id == "XSCAN-DNS-002"
    assert findings[0].severity is Severity.HIGH


def test_spf_correct_no_finding():
    assert spf_findings(["v=spf1 include:_spf.resend.com -all"]) == []


def test_dmarc_absent_is_medium():
    findings = dmarc_findings(["v=spf1 -all"])
    assert findings[0].id == "XSCAN-DNS-003"


def test_dmarc_present_no_finding():
    assert dmarc_findings(["v=DMARC1; p=quarantine; rua=mailto:x@t.test"]) == []
