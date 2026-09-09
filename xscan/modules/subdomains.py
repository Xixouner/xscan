from __future__ import annotations

import asyncio
import json

import httpx

from xscan.models import Finding, Severity

name = "subdomains"
passive = True
DESCRIPTION = "Sous-domaines via certificate transparency (crt.sh) et DNS"

_ID = "XSCAN-SUB"
_MAX_LISTED = 40
_MAX_RESOLVED = 100
_SENSITIVE_WORDS = (
    "staging", "stg", "dev", "test", "preprod", "uat", "admin", "vpn",
    "internal", "git", "jenkins", "grafana", "kibana", "api",
)


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    domain = httpx.URL(base_url).host
    if not domain:
        return []
    try:
        response = await client.get(
            f"https://crt.sh/?q=%.{domain}&output=json", follow_redirects=True, timeout=25.0,
        )
    except httpx.HTTPError:
        return [Finding(f"{_ID}-004", name, Severity.INFO, "crt.sh injoignable, lookup CT ignoré", domain, "—")]
    if response.status_code != 200:
        return [Finding(f"{_ID}-004", name, Severity.INFO, f"crt.sh a répondu {response.status_code}, lookup ignoré",
                        domain, "—")]
    subdomains = sorted(_parse_crt(response.text, domain))
    if not subdomains:
        return [Finding(f"{_ID}-001", name, Severity.INFO, "Aucun sous-domaine en CT logs", domain, "—")]
    findings = [Finding(f"{_ID}-001", name, Severity.INFO, f"{len(subdomains)} sous-domaines uniques en CT logs",
                        ", ".join(subdomains[:_MAX_LISTED]), "—")]
    resolved = await _resolve_many(subdomains, _MAX_RESOLVED)
    if resolved:
        findings.append(Finding(f"{_ID}-002", name, Severity.INFO, f"{len(resolved)} sous-domaines résolvent en DNS",
                                ", ".join(sorted(resolved)[:_MAX_LISTED]), "—"))
    sensitive = _sensitive_subdomains(subdomains)
    if sensitive:
        findings.append(Finding(f"{_ID}-003", name, Severity.LOW, "Sous-domaines potentiellement sensibles",
                                ", ".join(sensitive[:_MAX_LISTED]),
                                "Vérifier l'exposition de ces environnements (staging, admin, ...)."))
    return findings


def _parse_crt(payload: str, domain: str) -> set[str]:
    """Logique pure (testée) : sous-domaines uniques d'une réponse crt.sh."""
    try:
        entries = json.loads(payload)
    except json.JSONDecodeError:
        return set()
    subdomains: set[str] = set()
    for entry in entries if isinstance(entries, list) else []:
        raw = str(entry.get("name_value", ""))
        for candidate in raw.replace("*.", "").splitlines():
            candidate = candidate.strip().lower()
            if candidate.endswith(domain) and candidate != domain:
                subdomains.add(candidate)
    return subdomains


def _sensitive_subdomains(subdomains: list[str]) -> list[str]:
    """Logique pure (testée) : noms évoquant un environnement sensible."""
    return [sub for sub in subdomains if any(word in sub.split(".")[0] for word in _SENSITIVE_WORDS)]


async def _resolve_many(hosts: list[str], limit: int) -> set[str]:
    loop = asyncio.get_running_loop()

    async def resolve(host: str) -> str | None:
        try:
            await loop.getaddrinfo(host, None)
        except OSError:
            return None
        return host

    results = await asyncio.gather(*(resolve(host) for host in hosts[:limit]))
    return {host for host in results if host}
