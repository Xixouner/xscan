from __future__ import annotations

import asyncio
import ssl
from datetime import UTC, datetime

import httpx

from xscan.models import Finding, Severity

name = "transport"
passive = True
DESCRIPTION = "TLS, chaîne de redirection, version HTTP"

_MAX_HOPS = 10
_HOPS_WARN = 4
_CERT_EXPIRY_WARN_DAYS = 14


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    url = httpx.URL(base_url)
    findings = await _redirect_chain(client, base_url)
    if url.scheme == "http":
        findings.append(Finding("XSCAN-TRANSPORT-007", name, Severity.MEDIUM, "Cible servie en HTTP sans TLS",
                                base_url, "Forcer HTTPS avec une redirection 301."))
    if url.scheme == "https" and url.host:
        try:
            version, not_after = await _tls_info(url.host)
        except (ssl.SSLError, OSError):
            version, not_after = None, None
        findings.extend(_tls_findings(version, not_after))
    findings.extend(await _http_version(client, base_url))
    return findings


async def _redirect_chain(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    chain: list[str] = []
    url = base_url
    for _ in range(_MAX_HOPS):
        try:
            response = await client.get(url, follow_redirects=False)
        except httpx.HTTPError as exc:
            return [Finding("XSCAN-TRANSPORT-001", name, Severity.HIGH, "Cible injoignable", str(exc)[:120],
                            "Vérifier l'URL et la disponibilité de la cible.")]
        chain.append(f"{response.status_code} {url}")
        if not response.is_redirect:
            break
        location = response.headers.get("location", "")
        url = str(httpx.URL(url).join(location))
    findings = [Finding("XSCAN-TRANSPORT-002", name, Severity.INFO, "Chaîne de redirection",
                        " -> ".join(chain) or "—", "—")]
    if len(chain) >= _MAX_HOPS or (response.is_redirect if chain else False):
        findings.append(Finding("XSCAN-TRANSPORT-003", name, Severity.MEDIUM, "Chaîne de redirection anormale",
                                f"{len(chain)}+ sauts", "Réduire le nombre de redirections."))
    elif len(chain) > _HOPS_WARN:
        findings.append(Finding("XSCAN-TRANSPORT-003", name, Severity.LOW, "Chaîne de redirection longue",
                                f"{len(chain)} sauts", "Réduire le nombre de redirections."))
    return findings


async def _tls_info(host: str) -> tuple[str | None, float | None]:
    context = ssl.create_default_context()
    _, writer = await asyncio.open_connection(host, 443, ssl=context, server_hostname=host)
    try:
        sock = writer.get_extra_info("ssl_object")
        version = sock.version() if sock else None
        cert = sock.getpeercert() if sock else {}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    not_after = ssl.cert_time_to_seconds(cert["notAfter"]) if cert.get("notAfter") else None
    return version, not_after


def _tls_findings(version: str | None, not_after: float | None) -> list[Finding]:
    findings: list[Finding] = []
    if version and version not in ("TLSv1.2", "TLSv1.3"):
        findings.append(Finding("XSCAN-TRANSPORT-004", name, Severity.HIGH, f"Version TLS obsolète : {version}",
                                version, "Désactiver TLS < 1.2 sur le serveur."))
    if not_after:
        expires = datetime.fromtimestamp(not_after, tz=UTC)
        days_left = (expires - datetime.now(tz=UTC)).days
        if days_left < 0:
            findings.append(Finding("XSCAN-TRANSPORT-005", name, Severity.CRITICAL, "Certificat TLS expiré",
                                    f"expiré depuis {-days_left} j", "Renouveler le certificat immédiatement."))
        elif days_left <= _CERT_EXPIRY_WARN_DAYS:
            findings.append(Finding("XSCAN-TRANSPORT-006", name, Severity.MEDIUM, "Certificat TLS bientôt expiré",
                                    f"{days_left} j restants", "Programmer le renouvellement du certificat."))
        else:
            findings.append(Finding("XSCAN-TRANSPORT-009", name, Severity.INFO, f"Certificat valide ({days_left} j)",
                                    f"TLS: {version or 'inconnu'}", "—"))
    return findings


async def _http_version(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        response = await client.get(base_url, follow_redirects=True)
    except httpx.HTTPError:
        return []
    raw_version = response.extensions.get("http_version", "inconnu")
    http_version = raw_version.decode() if isinstance(raw_version, bytes) else str(raw_version or "inconnu")
    return [Finding("XSCAN-TRANSPORT-008", name, Severity.INFO, f"Protocole HTTP : {http_version}",
                    http_version, "—")]
