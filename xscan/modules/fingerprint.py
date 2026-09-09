from __future__ import annotations

import re

import httpx

from xscan.models import Finding, Severity

name = "fingerprint"
passive = True
DESCRIPTION = "Empreinte technique (serveur, framework, CDN, analytics)"

_ID = "XSCAN-FP"

_HEADER_HINTS: dict[str, dict[str, str]] = {
    "server": {
        "cloudflare": "Cloudflare", "nginx": "Nginx", "apache": "Apache",
        "litespeed": "LiteSpeed", "amazons3": "Amazon S3", "caddy": "Caddy",
    },
    "x-powered-by": {
        "next.js": "Next.js", "express": "Express", "php": "PHP", "asp.net": "ASP.NET",
    },
}
_HEADER_PRESENCE = {
    "x-vercel-id": "Vercel", "x-nf-request-id": "Netlify",
    "x-github-request-id": "GitHub Pages", "cf-ray": "Cloudflare",
}
_HTML_HINTS = [
    ("Next.js", "__NEXT_DATA__"), ("Next.js", "/_next/static"),
    ("Nuxt", "__NUXT__"), ("React", "__react"),
    ("WordPress", "/wp-content/"), ("Shopify", "cdn.shopify.com"),
    ("SvelteKit", "__sveltekit"), ("Astro", "astro-island"),
    ("Google Tag Manager", "googletagmanager.com"), ("Matomo", "matomo"),
]
_GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    response = await client.get(base_url, follow_redirects=True)
    return detect(response.headers, response.text)


def detect(headers: httpx.Headers, html: str) -> list[Finding]:
    """Logique pure (testable sans réseau) : retourne une finding par techno."""
    detected: dict[str, str] = {}
    for header, hints in _HEADER_HINTS.items():
        value = headers.get(header, "").lower()
        for needle, tech in hints.items():
            if needle in value:
                detected.setdefault(tech, f"header {header}: {value}")
    for header, tech in _HEADER_PRESENCE.items():
        if header in headers:
            detected.setdefault(tech, f"présence de l'en-tête {header}")
    for tech, needle in _HTML_HINTS:
        if needle.lower() in html.lower():
            detected.setdefault(tech, f"empreinte HTML: {needle}")
    for match in _GENERATOR_RE.finditer(html):
        detected.setdefault(f"Meta generator: {match.group(1)}", "meta generator")
    return [
        Finding(f"{_ID}-001", name, Severity.INFO, f"Technologie détectée : {tech}", evidence, "—")
        for tech, evidence in sorted(detected.items())
    ]
