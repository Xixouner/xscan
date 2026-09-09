from __future__ import annotations

import asyncio

import httpx

from xscan import web
from xscan.models import Finding, Severity

name = "redirects_open"
passive = False
DESCRIPTION = "Open redirects : paramètres de redirection réutilisables vers l'extérieur"

_ID = "XSCAN-REDIR"
_PROBE = "https://xscan-open-redirect.invalid"
_MAX_TESTS = 6
_DELAY_S = 0.1
_PARAMS = (
    "url", "next", "redirect", "redirect_uri", "redirect_url", "return",
    "returnto", "goto", "target", "dest", "destination", "continue", "link", "redir",
)


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
    """Logique pure (testée) : liens internes contenant un paramètre de redirection."""
    base = httpx.URL(page_url)
    candidates: list[str] = []
    for href in web.extract_hrefs(html_text):
        try:
            link = base.join(href)
        except ValueError:
            continue
        if link.host != base.host:
            continue
        suspects = _suspect_params(link)
        if suspects:
            candidates.append(str(link.copy_set_param(suspects[0], _PROBE)))
    return candidates


def _suspect_params(link: httpx.URL) -> list[str]:
    return [param for param in link.params if param.lower() in _PARAMS]


async def _test(client: httpx.AsyncClient, link: str) -> list[Finding]:
    try:
        response = await client.get(link, follow_redirects=False)
    except httpx.HTTPError:
        return []
    location = response.headers.get("location", "")
    if response.is_redirect and _PROBE in location:
        return [Finding(f"{_ID}-001", name, Severity.HIGH, "Redirection ouverte détectée",
                        f"{link[:70]} → {location[:60]}",
                        "Valider la destination contre une liste blanche avant de rediriger.")]
    return []
