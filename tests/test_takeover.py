from xscan.modules.takeover import takeover_findings
from xscan.models import Severity


def test_s3_takeover_detected():
    body = "<html><body><h1>NoSuchBucket</h1>The specified bucket does not exist.</body></html>"
    findings = takeover_findings("nonexistent-bucket.s3.amazonaws.com", body, "orphan.t.test")
    assert findings[0].severity is Severity.HIGH
    assert "AWS S3" in findings[0].title


def test_github_pages_takeover_detected():
    body = "<h1>There isn't a GitHub Pages site here.</h1>"
    assert takeover_findings("orphan.t.github.io", body, "orphan.t.test")


def test_claimed_service_not_flagged():
    body = "<html><body>Bienvenue sur le vrai site</body></html>"
    assert takeover_findings("real.s3.amazonaws.com", body, "sub.t.test") == []


def test_unrelated_body_no_finding():
    assert takeover_findings("random.other.com", "page normale", "sub.t.test") == []
