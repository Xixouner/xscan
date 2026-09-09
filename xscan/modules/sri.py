from __future__ import annotations

import re

import httpx

from xscan.models import Finding, Severity

name = "sri"
passive = True
DESCRIPTION = "Scripts tiers sans Subresource Integrity (risque supply chain)"

_ID = "XSCAN-SRI"
_SCRIPT_RE = re.compile(r"""<script\b([^>]*)>""", re.IGNORECASE)
_SRC_RE = re.compile(r"""src=["']([^"']+)["']""", re.IGNORECASE)
_INTEGRITY = "integrity="


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        page = await client.get(base_url, follow_redirects=True)
    except httpx.HTTPError:
        return []
    return analyze(page.text, str(page.url))


def analyze(html_text: str, page_url: str) -> list[Finding]:
    """Logique pure (testée) : scripts cross-origin sans attribut integrity."""
    base = httpx.URL(page_url)
    unprotected: list[str] = []
    for attrs in _SCRIPT_RE.findall(html_text):
        match = _SRC_RE.search(attrs)
        if not match:
            continue
        source = base.join(match.group(1))
        if source.host and source.host != base.host and _INTEGRITY not in attrs.lower():
            unprotected.append(str(source))
    if not unprotected:
        return []
    return [Finding(f"{_ID}-001", name, Severity.LOW,
                    f"{len(unprotected)} script(s) tiers sans Subresource Integrity",
                    "; ".join(unprotected[:5]),
                    "Ajouter integrity=\"sha384-...\" et crossorigin=\"anonymous\" aux scripts externes.")]
