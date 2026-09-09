from __future__ import annotations

import httpx

from xscan.models import Finding, Severity

name = "xsleaks"
passive = True
DESCRIPTION = "Politiques d'isolation cross-origin (COOP/COEP/CORP) — XS-Leaks"

_ID = "XSCAN-XSL"


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        response = await client.get(base_url, follow_redirects=True)
    except httpx.HTTPError:
        return []
    return analyze(response.headers)


def analyze(headers: httpx.Headers) -> list[Finding]:
    """Logique pure (testée) : politiques d'isolation modernes."""
    findings: list[Finding] = []
    if "cross-origin-opener-policy" not in headers:
        findings.append(Finding(f"{_ID}-001", name, Severity.LOW,
                                "Cross-Origin-Opener-Policy absent (XS-Leaks via popups/opener)",
                                "en-tête absent", "Ajouter Cross-Origin-Opener-Policy: same-origin."))
    if "cross-origin-embedder-policy" not in headers:
        findings.append(Finding(f"{_ID}-002", name, Severity.INFO,
                                "Cross-Origin-Embedder-Policy absent",
                                "en-tête absent", "Envisager COEP: require-corp si les ressources le permettent."))
    if "cross-origin-resource-policy" not in headers:
        findings.append(Finding(f"{_ID}-003", name, Severity.INFO,
                                "Cross-Origin-Resource-Policy absent",
                                "en-tête absent", "CORP: same-origin limite la lecture cross-origin des ressources."))
    return findings
