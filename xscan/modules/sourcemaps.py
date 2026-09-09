from __future__ import annotations

import asyncio

import httpx

from xscan import web
from xscan.models import Finding, Severity

name = "sourcemaps"
passive = False
DESCRIPTION = "Source maps (.map) exposées : fuite du code source original"

_ID = "XSCAN-SMAP"
_MAX_SCRIPTS = 8


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        page = await client.get(base_url, follow_redirects=True)
    except httpx.HTTPError:
        return []
    base = httpx.URL(str(page.url))
    js_urls = [str(base.join(src)) for src in web.extract_script_srcs(page.text)
               if base.join(src).path.endswith(".js")][:_MAX_SCRIPTS]
    probes = [_probe(client, js_url) for js_url in js_urls]
    return [finding for finding in await asyncio.gather(*probes) if finding is not None]


async def _probe(client: httpx.AsyncClient, js_url: str) -> Finding | None:
    try:
        response = await client.get(map_url_for(js_url), follow_redirects=True)
    except httpx.HTTPError:
        return None
    if is_sourcemap(response.status_code, response.text[:4096]):
        return Finding(f"{_ID}-001", name, Severity.MEDIUM, "Source map exposée : code source original accessible",
                       map_url_for(js_url)[:100], "Ne pas déployer les fichiers .map en production.")
    return None


def map_url_for(js_url: str) -> str:
    """Logique pure (testée)."""
    return js_url + ".map"


def is_sourcemap(status: int, body: str) -> bool:
    """Logique pure (testée) : JSON de source map (une page SPA 404 n'a jamais mappings+sources)."""
    if status != 200:
        return False
    stripped = body.lstrip()
    return stripped.startswith("{") and '"sources"' in stripped and '"mappings"' in stripped
