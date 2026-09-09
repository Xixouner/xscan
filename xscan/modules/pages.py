from __future__ import annotations

import asyncio
import re

import httpx

from xscan.models import Finding, Severity

name = "pages"
passive = False
DESCRIPTION = "Crawl interne : contenu mixte HTTPS, stack traces exposées"

_ID = "XSCAN-PAGES"
_MAX_PAGES = 12
_LINKS_PER_PAGE = 5
_DELAY_S = 0.05
_SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".pdf", ".zip", ".ico", ".woff", ".woff2")
_MIXED_RE = re.compile(r"""(?:src|href)=["']http://[^"']+["']""", re.IGNORECASE)
_STACK_PATTERNS = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)"), Severity.HIGH),
    ("PHP warning/error", re.compile(r"(?:Warning|Fatal error|Parse error): .+ in /"), Severity.MEDIUM),
    ("SQL error", re.compile(r"(SQL syntax|SQLSTATE\[|ORA-\d{5}|MySQLSyntaxErrorException)"), Severity.HIGH),
    ("Java exception", re.compile(r"java\.lang\.\w+Exception"), Severity.MEDIUM),
    (".NET exception", re.compile(r"System\.\w+Exception|Server Error in '/'"), Severity.MEDIUM),
    ("Django/Rails debug", re.compile(r"Action Controller: exception caught|DEBUG = True"), Severity.MEDIUM),
]


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    pages = await _crawl(client, base_url)
    findings: list[Finding] = []
    for page_url, html_text in pages:
        findings.extend(_page_findings(page_url, html_text))
    return findings


async def _crawl(client: httpx.AsyncClient, base_url: str) -> list[tuple[str, str]]:
    visited: set[str] = set()
    queue = [base_url]
    results: list[tuple[str, str]] = []
    while queue and len(results) < _MAX_PAGES:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            response = await client.get(url, follow_redirects=True)
        except httpx.HTTPError:
            continue
        content_type = response.headers.get("content-type", "").lower()
        if response.status_code != 200 or "text/html" not in content_type:
            continue
        results.append((str(response.url), response.text))
        queue.extend(_internal_links(str(response.url), response.text)[:_LINKS_PER_PAGE])
        await asyncio.sleep(_DELAY_S)
    return results


def _internal_links(page_url: str, html_text: str) -> list[str]:
    """Logique pure (testée) : liens internes (même host), hors fragments et médias."""
    base = httpx.URL(page_url)
    links: list[str] = []
    for href in re.findall(r"""href=["']([^"'#]+)""", html_text):
        try:
            link = base.join(href)
        except ValueError:
            continue
        if link.host != base.host or link.path.lower().endswith(_SKIP_SUFFIXES):
            continue
        absolute = str(link)
        if absolute not in links:
            links.append(absolute)
    return links


def _page_findings(page_url: str, html_text: str) -> list[Finding]:
    findings: list[Finding] = []
    if page_url.startswith("https://"):
        matches = _MIXED_RE.findall(html_text)
        if matches:
            findings.append(Finding(f"{_ID}-001", name, Severity.MEDIUM,
                                    "Contenu mixte : ressources HTTP chargées sur une page HTTPS",
                                    ", ".join(match[:50] for match in matches[:3]),
                                    "Servir toutes les ressources en HTTPS."))
    for label, pattern, severity in _STACK_PATTERNS:
        if pattern.search(html_text):
            findings.append(Finding(f"{_ID}-002", name, severity,
                                    f"Stack trace / erreur technique exposée ({label})", page_url,
                                    "Désactiver le mode debug et masquer les erreurs brutes en production."))
    return findings
