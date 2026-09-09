from xscan.modules.tls_deep import chain_findings
from xscan.models import Severity


def test_unverified_chain_is_high():
    findings = chain_findings(False, ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128))
    assert any(finding.id == "XSCAN-TLS020" and finding.severity is Severity.HIGH for finding in findings)


def test_weak_cipher_is_medium():
    findings = chain_findings(True, ("EXP-RC4-MD5", "TLSv1.0", 40))
    assert any(finding.id == "XSCAN-TLS021" and finding.severity is Severity.MEDIUM for finding in findings)


def test_strong_cipher_is_info_only():
    findings = chain_findings(True, ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256))
    assert len(findings) == 1
    assert findings[0].id == "XSCAN-TLS022"
    assert findings[0].severity is Severity.INFO


def test_no_cipher_no_crash():
    assert chain_findings(True, None) == []
