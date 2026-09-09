from __future__ import annotations

import asyncio

import httpx

from xscan.models import Finding, Severity

name = "ports"
passive = False
DESCRIPTION = "Services sensibles (DB, Redis, RDP...) exposés publiquement (TCP connect)"

_ID = "XSCAN-PORT"
_TIMEOUT = 3.0
_CHECKS = [
    (21, "FTP", Severity.LOW),
    (23, "Telnet", Severity.HIGH),
    (445, "SMB", Severity.HIGH),
    (3306, "MySQL", Severity.MEDIUM),
    (3389, "RDP", Severity.MEDIUM),
    (5432, "PostgreSQL", Severity.MEDIUM),
    (6379, "Redis", Severity.HIGH),
    (9200, "Elasticsearch", Severity.HIGH),
    (27017, "MongoDB", Severity.CRITICAL),
]


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    host = httpx.URL(base_url).host
    if not host:
        return []
    probes = [_probe(host, port, service, severity) for port, service, severity in _CHECKS]
    return [finding for finding in await asyncio.gather(*probes) if finding is not None]


async def _probe(host: str, port: int, service: str, severity: Severity) -> Finding | None:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=_TIMEOUT)
    except (TimeoutError, OSError):
        return None  # fermé (refus) ou filtré (drop) : rien à signaler
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return Finding(f"{_ID}-{port}", name, severity, f"Port {port} ({service}) accessible publiquement",
                   f"tcp/{port} connecté sur {host}", "Restreindre ce service (firewall ou bind 127.0.0.1).")
