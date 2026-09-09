from __future__ import annotations

import httpx

from xscan.models import Finding, Severity

name = "http_deep"
passive = False
DESCRIPTION = "Méthodes HTTP risquées, Host header reflection, security.txt"

_ID = "XSCAN-HTTP"
_RISKY_METHODS = ("PUT", "DELETE", "TRACE", "CONNECT")
_PROBE_HOST = "xscan-probe.invalid"


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(await _trace(client, base_url))
    findings.extend(await _options(client, base_url))
    findings.extend(await _host_reflection(client, base_url))
    findings.extend(await _security_txt(client, base_url))
    return findings


async def _trace(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        response = await client.request("TRACE", base_url, follow_redirects=False)
    except httpx.HTTPError:
        return []
    if response.status_code < 400:
        return [Finding(f"{_ID}-001", name, Severity.MEDIUM, "Méthode TRACE activée (risque Cross-Site Tracing)",
                        f"status {response.status_code}", "Désactiver TRACE sur le serveur web.")]
    return []


async def _options(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        response = await client.request("OPTIONS", base_url, follow_redirects=False)
    except httpx.HTTPError:
        return []
    return allow_findings(response.headers.get("allow", ""))


def allow_findings(allow_header: str) -> list[Finding]:
    """Logique pure (testée) : méthodes risquées annoncées par OPTIONS."""
    announced = {method.strip().upper() for method in allow_header.split(",")}
    risky = sorted(set(_RISKY_METHODS) & announced)
    if risky:
        return [Finding(f"{_ID}-002", name, Severity.MEDIUM, f"Méthodes HTTP risquées annoncées : {', '.join(risky)}",
                        allow_header or "(vide)", "Désactiver ces méthodes si elles ne sont pas utilisées.")]
    return []


async def _host_reflection(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        response = await client.get(base_url, headers={"Host": _PROBE_HOST}, follow_redirects=False)
    except httpx.HTTPError:
        return []
    return reflection_findings(response.headers.get("location", ""), response.text[:2048], _PROBE_HOST)


def reflection_findings(location: str, body: str, probe_host: str) -> list[Finding]:
    """Logique pure (testée) : le serveur reflète-t-il un Host forgé ?"""
    if probe_host in location or probe_host in body:
        return [Finding(f"{_ID}-003", name, Severity.MEDIUM,
                        "Le serveur reflète le header Host (risque de host/cache poisoning)",
                        probe_host, "Ne jamais construire d'URLs à partir du Host reçu.")]
    return []


async def _security_txt(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    for path in (".well-known/security.txt", "security.txt"):
        try:
            response = await client.get(str(httpx.URL(base_url).join(path)), follow_redirects=True)
        except httpx.HTTPError:
            continue
        if response.status_code == 200 and "text/plain" in response.headers.get("content-type", "").lower():
            return [Finding(f"{_ID}-004", name, Severity.INFO, "security.txt présent (RFC 9116)", path, "—")]
    return [Finding(f"{_ID}-005", name, Severity.LOW, "Pas de /.well-known/security.txt (RFC 9116)",
                    "Fichier absent", "Publier un security.txt avec un contact pour les chercheurs en sécurité.")]
