from __future__ import annotations

import httpx

_DOH = "https://cloudflare-dns.com/dns-query"


async def dns_query(client: httpx.AsyncClient, name: str, rrtype: str) -> list[str]:
    """Requête DNS-over-HTTPS (Cloudflare, JSON). [] si erreur, NXDOMAIN ou timeout."""
    try:
        response = await client.get(
            _DOH, params={"name": name, "type": rrtype},
            headers={"Accept": "application/dns-json"}, follow_redirects=True,
        )
    except httpx.HTTPError:
        return []
    if response.status_code != 200:
        return []
    try:
        data = response.json()
    except ValueError:
        return []
    if data.get("Status") != 0:
        return []
    return [str(answer.get("data", "")) for answer in data.get("Answer", [])]
