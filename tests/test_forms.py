from xscan.modules import forms


def test_password_post_without_csrf_flagged():
    html = '<form action="/login" method="post"><input type="password" name="pwd"><input type="submit"></form>'
    findings = forms.analyze_forms(html, "https://t.test/login")
    ids = {finding.id for finding in findings}
    assert "XSCAN-FORMS-003" in ids
    assert "XSCAN-FORMS-001" not in ids
    assert "XSCAN-FORMS-002" not in ids


def test_csrf_hidden_input_silences():
    html = ('<form action="/login" method="post">'
            '<input type="hidden" name="csrf_token" value="x"><input type="password" name="pwd"></form>')
    ids = {finding.id for finding in forms.analyze_forms(html, "https://t.test/login")}
    assert "XSCAN-FORMS-003" not in ids


def test_password_over_http_is_high():
    html = '<form method="post"><input type="password" name="pwd"></form>'
    findings = forms.analyze_forms(html, "http://t.test/login")
    assert any(finding.id == "XSCAN-FORMS-001" and finding.severity.value == "high" for finding in findings)


def test_password_get_flagged():
    html = '<form action="/login" method="get"><input type="password" name="pwd"></form>'
    assert any(finding.id == "XSCAN-FORMS-002" for finding in forms.analyze_forms(html, "https://t.test/login"))


def test_cross_origin_password_action_flagged():
    html = '<form action="https://tiers.test/collect" method="post"><input type="password" name="pwd"></form>'
    assert any(finding.id == "XSCAN-FORMS-004" for finding in forms.analyze_forms(html, "https://t.test/login"))


def test_no_form_no_finding():
    assert forms.analyze_forms("<p>pas de formulaire</p>", "https://t.test/") == []
