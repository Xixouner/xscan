from __future__ import annotations

import asyncio

import httpx

from xscan.models import Finding, Severity

name = "robots"
passive = False
DESCRIPTION = "Chemins révélés par robots.txt (content discovery ciblé)"

_ID = "XSCAN-ROB"


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    from xscan.modules.exposure import plausible_content

    try:
        response = await client.get(str(httpx.URL(base_url).join("robots.txt")), follow_redirects=True)
    except httpx.HTTPError:
        return []
    if response.status_code != 200 or "disallow" not in response.text.lower():
        return []
    findings: list[Finding] = []
    base = httpx.URL(base_url)
    for index, path in enumerate(disallow_paths(response.text)[:15]):
        probe_url = str(base.join(path.lstrip("/")))
        try:
            probe = await client.get(probe_url, follow_redirects=False)
        except httpx.HTTPError:
            continue
        if probe.status_code == 200 and plausible_content(None, probe.text[:4096], probe.headers):
            findings.append(Finding(f"{_ID}-001", name, Severity.MEDIUM,
                                    f"Chemin révélé par robots.txt et accessible : {path}",
                                    probe_url[:90],
                                    "Ne pas lister les chemins sensibles dans robots.txt, les protéger côté serveur."))
        await asyncio.sleep(0.1)
    if "sitemap:" in response.text.lower():
        findings.append(Finding(f"{_ID}-002", name, Severity.INFO, "Sitemap déclaré dans robots.txt",
                                response.text.lower().split("sitemap:")[1].split()[0][:80], "—"))
    return findings


def disallow_paths(robots_text: str) -> list[str]:
    """Logique pure (testée) : chemins Disallow exploitables (hors / et *)."""
    paths: list[str] = []
    for line in robots_text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path not in ("/", "*") and path not in paths:
                paths.append(path)
    return paths
