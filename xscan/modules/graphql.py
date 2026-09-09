from __future__ import annotations

import asyncio

import httpx

from xscan.models import Finding, Severity

name = "graphql"
passive = False
DESCRIPTION = "Endpoints GraphQL : introspection de schéma exposée"

_ID = "XSCAN-GQL"
_CANDIDATES = ("graphql", "api/graphql", "graphiql", "graphql/v1")
_INTROSPECTION_QUERY = {"query": "{__schema{types{name}}}"}


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    for path in _CANDIDATES:
        url = str(httpx.URL(base_url).join(path))
        try:
            response = await client.post(url, json=_INTROSPECTION_QUERY, follow_redirects=False)
        except httpx.HTTPError:
            continue
        body = response.text[:4096]
        if introspection_open(response.status_code, body):
            findings.append(Finding(f"{_ID}-001", name, Severity.MEDIUM,
                                    f"Introspection GraphQL exposée : {path}",
                                    "__schema renvoyé — tout le schéma de l'API est lisible",
                                    "Désactiver l'introspection en production."))
            break
        if graphql_detected(body):
            findings.append(Finding(f"{_ID}-002", name, Severity.INFO,
                                    f"Endpoint GraphQL détecté : {path} (introspection fermée)", path, "—"))
            break
        await asyncio.sleep(0.1)
    return findings


def introspection_open(status: int, body: str) -> bool:
    """Logique pure (testée) : __schema renvoyé = schéma exposé."""
    return status == 200 and "__schema" in body


def graphql_detected(body: str) -> bool:
    """Logique pure (testée) : messages d'erreur typiques d'un endpoint GraphQL."""
    lowered = body.lower()
    return "get query missing" in lowered or "must provide query string" in lowered
