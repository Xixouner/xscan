from __future__ import annotations

import asyncio

import httpx

from xscan import web
from xscan.models import Finding, Severity

name = "xss_probe"
passive = False
DESCRIPTION = "Réflexion brute de paramètres (candidats XSS à vérifier)"

_ID = "XSCAN-XSS"
_MARKER = 'xs7q"\'>(mrk)'
_MAX_TESTS = 6
_DELAY_S = 0.1


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        page = await client.get(base_url, follow_redirects=True)
    except httpx.HTTPError:
        return []
    candidates = candidate_links(page.text, str(page.url))[:_MAX_TESTS]
    findings: list[Finding] = []
    for link in candidates:
        findings.extend(await _test(client, link))
        await asyncio.sleep(_DELAY_S)
    return findings


def candidate_links(html_text: str, page_url: str) -> list[str]:
    """Logique pure (testée) : liens internes avec paramètres, marqueur injecté."""
    base = httpx.URL(page_url)
    candidates: list[str] = []
    for href in web.extract_hrefs(html_text):
        try:
            link = base.join(href)
        except ValueError:
            continue
        if link.host == base.host and link.params and str(link) not in candidates:
            first = next(iter(link.params))
            candidates.append(str(link.copy_set_param(first, _MARKER)))
    return candidates


async def _test(client: httpx.AsyncClient, link: str) -> list[Finding]:
    try:
        response = await client.get(link, follow_redirects=True)
    except httpx.HTTPError:
        return []
    return reflection_findings(response.text, link)


def reflection_findings(body: str, link: str) -> list[Finding]:
    """Logique pure (testée) : marqueur avec quotes reflété SANS échappement HTML."""
    if _MARKER in body:
        return [Finding(f"{_ID}-001", name, Severity.MEDIUM,
                        "Paramètre reflété sans échappement HTML — candidat XSS",
                        f"{link[:70]} (marqueur reflété brut)",
                        "Vérifier le contexte manuellement et encoder selon le contexte (HTML, attribut, JS).")]
    return []
