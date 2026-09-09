from xscan.modules.privacy import detect


def test_trackers_detected():
    html = '<script src="https://www.googletagmanager.com/gtag/js"></script><img src="https://static.hotjar.com/x">'
    findings = detect(html, [])
    assert findings[0].id == "XSCAN-PRIV-001"
    assert "Google Tag Manager" in findings[0].title and "Hotjar" in findings[0].title


def test_no_tracker_no_finding():
    assert detect("<p>site sans tracker</p>", []) == []


def test_cookies_counted():
    findings = detect("<p>propre</p>", ["sid=abc; HttpOnly", "theme=dark"])
    assert any(finding.id == "XSCAN-PRIV-002" and "2" in finding.title for finding in findings)
