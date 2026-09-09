import asyncio

import httpx

from xscan.models import Severity
from xscan.modules import exposure


def test_find_secrets_labels_and_masks():
    fake = "sk_" + "live_" + "a" * 24  # construit à l'exécution : un literal déclencherait la push protection GitHub
    found = exposure.find_secrets(f"token: {fake}")
    assert found[0][0] == "Stripe clé live"
    assert found[0][2].startswith("sk_liv")
    assert "…" in found[0][2]
    assert fake not in found[0][2]


def test_no_secret_in_clean_text():
    assert exposure.find_secrets("une page tout à fait normale, sans secret") == []


def test_env_pattern_discriminates():
    pattern = dict((path, pat) for path, _, pat in exposure._CHECKS)[".env"]
    assert exposure.plausible_content(pattern, "DATABASE_URL=postgres://u:p@h/db\n", httpx.Headers())
    assert not exposure.plausible_content(pattern, "<!DOCTYPE html><html><body>404</body></html>", httpx.Headers())


def test_non_html_content_required_for_binary_paths():
    assert not exposure.plausible_content(None, "<html>SPA fallback</html>", httpx.Headers({"content-type": "text/html"}))
    assert exposure.plausible_content(None, "binary-stuff", httpx.Headers({"content-type": "application/octet-stream"}))


def test_env_endpoint_reports_critical():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.env":
            return httpx.Response(200, text="DATABASE_URL=postgres://u:p@h/db\n")
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    findings = asyncio.run(exposure.run(client, "https://cible.test/"))
    assert any(finding.severity is Severity.CRITICAL and ".env" in finding.title for finding in findings)
