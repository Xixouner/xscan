from __future__ import annotations

import httpx

from xscan.models import Finding, Severity

name = "privacy"
passive = True
DESCRIPTION = "Trackers et cookies détectés (transparence RGPD)"

_ID = "XSCAN-PRIV"
_TRACKERS = {
    "googletagmanager.com": "Google Tag Manager",
    "google-analytics.com": "Google Analytics",
    "connect.facebook.net": "Facebook Pixel",
    "static.hotjar.com": "Hotjar",
    "snap.licdn.com": "LinkedIn Insight Tag",
    "analytics.tiktok.com": "TikTok Pixel",
    "clarity.ms": "Microsoft Clarity",
    "plausible.io": "Plausible",
}


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        response = await client.get(base_url, follow_redirects=True)
    except httpx.HTTPError:
        return []
    return detect(response.text.lower(), response.headers.get_list("set-cookie"))


def detect(html_text: str, set_cookies: list[str]) -> list[Finding]:
    """Logique pure (testée) : trackers embarqués, rappel RGPD."""
    found = sorted({provider for needle, provider in _TRACKERS.items() if needle in html_text})
    findings: list[Finding] = []
    if found:
        findings.append(Finding(f"{_ID}-001", name, Severity.INFO,
                                f"{len(found)} tracker(s) tiers : {', '.join(found)}",
                                "vérifier le consentement préalable (RGPD/ePrivacy)",
                                "Bannière de consentement et politique de confidentialité à jour."))
    if set_cookies:
        findings.append(Finding(f"{_ID}-002", name, Severity.INFO,
                                f"{len(set_cookies)} cookie(s) posé(s) dès la première visite",
                                "; ".join(cookie.split("=")[0] for cookie in set_cookies[:5]),
                                "Sans consentement, seuls les cookies strictement nécessaires sont autorisés."))
    return findings
