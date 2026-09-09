from __future__ import annotations

import asyncio
import ssl

import httpx

from xscan.models import Finding, Severity

name = "tls_deep"
passive = True
DESCRIPTION = "Protocoles TLS legacy, validité de la chaîne, force du cipher"

_ID = "XSCAN-TLS"
_LEGACY = [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    url = httpx.URL(base_url)
    if url.scheme != "https" or not url.host:
        return []
    findings: list[Finding] = []
    for label, version in _LEGACY:
        if await _handshake_ok(url.host, version):
            findings.append(Finding(f"{_ID}010", name, Severity.MEDIUM, f"Protocole {label} encore accepté",
                                    f"handshake {label} réussi sur {url.host}", "Désactiver les protocoles TLS < 1.2."))
    findings.extend(await _chain_and_cipher(url.host))
    findings.extend(await _hsts_preload(client, url.host))
    return findings


async def _hsts_preload(client: httpx.AsyncClient, host: str) -> list[Finding]:
    """Liste de préchargement HSTS des navigateurs (API publique hstspreload.org)."""
    try:
        response = await client.get(f"https://hstspreload.org/api/v2/status?domain={host}", follow_redirects=True)
        status = str(response.json().get("status", "unknown"))
    except (httpx.HTTPError, ValueError):
        return []
    if status in ("unknown", "absent"):
        return [Finding(f"{_ID}030", name, Severity.INFO, "Domaine absent de la HSTS preload list",
                        f"statut : {status}",
                        "Une fois HSTS stable (max-age long + preload), soumettre sur hstspreload.org.")]
    return [Finding(f"{_ID}031", name, Severity.INFO, f"HSTS preload : {status}", host, "—")]


async def _handshake_ok(host: str, version: ssl.TLSVersion) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = version
    context.maximum_version = version
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=context, server_hostname=host), timeout=6)
    except (TimeoutError, ssl.SSLError, OSError, ValueError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


async def _chain_and_cipher(host: str) -> list[Finding]:
    verified = True
    try:
        writer = await _connect(host, ssl.create_default_context())
    except ssl.SSLCertVerificationError:
        verified = False
        writer = await _connect(host, _unverified())
    except OSError:
        return []
    try:
        cipher = writer.get_extra_info("ssl_object").cipher()
    finally:
        await _close(writer)
    return chain_findings(verified, cipher)


def chain_findings(verified: bool, cipher: tuple | None) -> list[Finding]:
    """Logique pure (testée) : chaîne invalide, cipher faible, cipher négocié."""
    findings: list[Finding] = []
    if not verified:
        findings.append(Finding(f"{_ID}020", name, Severity.HIGH, "Chaîne de certificats TLS invalide/incomplète",
                                "vérification du certificat échouée", "Installer le certificat intermédiaire manquant."))
    if cipher and cipher[2] < 128:
        findings.append(Finding(f"{_ID}021", name, Severity.MEDIUM,
                                f"Cipher faible : {cipher[0]} ({cipher[2]} bits)", str(cipher),
                                "Exiger des ciphers >= 128 bits (AES-256-GCM, ChaCha20)."))
    elif cipher:
        findings.append(Finding(f"{_ID}022", name, Severity.INFO,
                                f"Cipher négocié : {cipher[0]} ({cipher[2]} bits)", str(cipher), "—"))
    return findings


def _unverified() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def _connect(host: str, context: ssl.SSLContext):
    _, writer = await asyncio.wait_for(
        asyncio.open_connection(host, 443, ssl=context, server_hostname=host), timeout=6)
    return writer


async def _close(writer) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
