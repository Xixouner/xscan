from __future__ import annotations

import asyncio

import httpx

from xscan.doh import dns_query
from xscan.models import Finding, Severity
from xscan.modules.subdomains import _parse_crt

name = "takeover"
passive = True
DESCRIPTION = "Subdomain takeover : CNAME vers un service cloud non réclamé"

_ID = "XSCAN-TKO"
_CRT_SH = "https://crt.sh/?q=%.{domain}&output=json"
_MAX_SUBDOMAINS = 15
_SIGNERS = [
    ("s3.amazonaws.com", "nosuchbucket", "AWS S3"),
    ("github.io", "there isn't a github pages site here", "GitHub Pages"),
    ("herokuapp.com", "no such app", "Heroku"),
    ("azurewebsites.net", "404 web site not found", "Azure"),
    ("cloudfront.net", "the request could not be satisfied", "CloudFront"),
    ("myshopify.com", "sorry, this shop is currently unavailable", "Shopify"),
    ("zendesk.com", "help center closed", "Zendesk"),
    ("tumblr.com", "there's nothing here", "Tumblr"),
    ("squarespace.com", "website expired", "Squarespace"),
    ("webflow.io", "the page you are looking for doesn't exist", "Webflow"),
    ("ghost.io", "the thing you were looking for is no longer here", "Ghost"),
    ("readme.io", "project doesnt exist... yet!", "Readme"),
]


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    domain = httpx.URL(base_url).host
    if not domain:
        return []
    try:
        response = await client.get(_CRT_SH.format(domain=domain), follow_redirects=True, timeout=25.0)
    except httpx.HTTPError:
        return []
    if response.status_code != 200:
        return []
    subdomains = sorted(_parse_crt(response.text, domain))[:_MAX_SUBDOMAINS]
    probes = [_probe(client, sub) for sub in subdomains]
    return [finding for finding in await asyncio.gather(*probes) if finding is not None]


async def _probe(client: httpx.AsyncClient, subdomain: str) -> Finding | None:
    cname_records = await dns_query(client, subdomain, "CNAME")
    suffixes = [suffix for suffix, _, _ in _SIGNERS]
    target = next((record.rstrip(".") for record in cname_records
                   if any(suffix in record.lower() for suffix in suffixes)), None)
    if target is None:
        return None
    try:
        response = await client.get(f"https://{subdomain}", follow_redirects=True)
    except httpx.HTTPError:
        return None
    return takeover_findings(target, response.text[:2048], subdomain)


def takeover_findings(cname_target: str, body: str, subdomain: str) -> list[Finding]:
    """Logique pure (testée) : signature d'un service cloud non réclamé."""
    lowered = body.lower()
    for suffix, signature, provider in _SIGNERS:
        if suffix in cname_target.lower() and signature in lowered:
            return [Finding(f"{_ID}-001", name, Severity.HIGH,
                            f"Subdomain takeover possible : {subdomain} → {provider}",
                            f"CNAME {cname_target} — signature « {signature[:40]} »",
                            f"Réclamer le sous-domaine sur {provider} ou supprimer le CNAME orphelin.")]
    return []
