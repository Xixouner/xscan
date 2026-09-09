from __future__ import annotations

import httpx

from xscan.models import Finding, Severity

name = "waf"
passive = True
DESCRIPTION = "Détection de WAF / CDN en amont (Cloudflare, Akamai, Sucuri...)"

_ID = "XSCAN-WAF"
_HEADER_PRESENCE = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-sucuri-id": "Sucuri WAF",
    "x-akamai-transformed": "Akamai",
    "x-iinfo": "Imperva Incapsula",
    "x-fastly-request-id": "Fastly",
    "x-amz-cf-id": "AWS CloudFront",
    "x-cdn": "CDN générique",
}
_COOKIE_HINTS = {
    "__cf_bm": "Cloudflare Bot Management",
    "__cfruid": "Cloudflare",
    "ak_bmsc": "Akamai Bot Manager",
    "bm_sv": "Akamai",
}


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        response = await client.get(base_url, follow_redirects=True)
    except httpx.HTTPError:
        return []
    return detect(response.headers, response.headers.get_list("set-cookie"))


def detect(headers: httpx.Headers, set_cookies: list[str]) -> list[Finding]:
    """Logique pure (testée) : empreinte du WAF/CDN en amont."""
    detected: dict[str, str] = {}
    for header, provider in _HEADER_PRESENCE.items():
        if header in headers:
            detected.setdefault(provider, f"en-tête {header}")
    for cookie in set_cookies:
        for hint, provider in _COOKIE_HINTS.items():
            if hint in cookie:
                detected.setdefault(provider, f"cookie {hint}")
    return [
        Finding(f"{_ID}-001", name, Severity.INFO, f"WAF/CDN détecté : {provider}", evidence,
                "Le scan peut être filtré : les détections nuclei seront aussi médiatisées par ce WAF.")
        for provider, evidence in sorted(detected.items())
    ]
