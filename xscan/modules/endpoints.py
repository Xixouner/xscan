from __future__ import annotations

import asyncio
import re

import httpx

from xscan import web
from xscan.models import Finding, Severity

name = "endpoints"
passive = True
DESCRIPTION = "Endpoints et chemins révélés dans le JavaScript livré"

_ID = "XSCAN-EP"
_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./]{1,60})["'`]""")
_INTERESTING = re.compile(r"(?i)(api|admin|debug|config|token|auth|upload|graphql|backup|\.sql|\.json|internal)")
_MAX_SCRIPTS = 10


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        page = await client.get(base_url, follow_redirects=True)
    except httpx.HTTPError:
        return []
    script_urls = [str(web.resolve(str(page.url), src)) for src in web.extract_script_srcs(page.text)][:_MAX_SCRIPTS]
    sources = await asyncio.gather(*(_fetch(client, url) for url in script_urls))
    paths: set[str] = set()
    for js in sources:
        paths |= _extract_paths(js)
    if not paths:
        return []
    findings = [Finding(f"{_ID}-001", name, Severity.INFO, f"{len(paths)} chemins distincts extraits des scripts JS",
                        ", ".join(sorted(paths)[:40]), "—")]
    interesting = sorted(path for path in paths if _INTERESTING.search(path))
    if interesting:
        findings.append(Finding(f"{_ID}-002", name, Severity.LOW, "Chemins potentiellement sensibles dans le JS",
                                ", ".join(interesting[:40]),
                                "Vérifier que ces endpoints exigent une authentification."))
    return findings


async def _fetch(client: httpx.AsyncClient, url: str) -> str:
    try:
        return (await client.get(url, follow_redirects=True)).text
    except httpx.HTTPError:
        return ""


def _extract_paths(js: str) -> set[str]:
    """Logique pure (testée) : chemins absolus cités dans le code JS."""
    return set(_PATH_RE.findall(js))
