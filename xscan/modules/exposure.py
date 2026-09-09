from __future__ import annotations

import asyncio
import re

import httpx

from xscan.models import Finding, Severity

name = "exposure"
passive = False
DESCRIPTION = "Fichiers sensibles exposés et secrets dans les pages/JS"

_ID = "XSCAN-EXPOSURE"
_DELAY_S = 0.1
_MAX_SCRIPTS = 8

_ENV_PATTERN = re.compile(r"(?m)^[A-Z][A-Z0-9_]*\s*=")
_CHECKS = [
    (".env", Severity.CRITICAL, _ENV_PATTERN),
    (".env.local", Severity.CRITICAL, _ENV_PATTERN),
    (".env.production", Severity.CRITICAL, _ENV_PATTERN),
    (".git/HEAD", Severity.HIGH, re.compile(r"^ref: refs/")),
    (".DS_Store", Severity.LOW, None),
    ("server-status", Severity.LOW, None),
    ("actuator/health", Severity.MEDIUM, None),
]
_SECRET_PATTERNS = [
    ("Clé AWS", Severity.CRITICAL, re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Stripe clé live", Severity.CRITICAL, re.compile(r"(sk|rk)_live_[0-9A-Za-z]{16,}")),
    ("Token GitHub", Severity.HIGH, re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("Token Slack", Severity.HIGH, re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Clé Resend", Severity.HIGH, re.compile(r"re_[A-Za-z0-9]{20,}")),
    ("Clé Google API", Severity.HIGH, re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("Clé privée", Severity.CRITICAL, re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
_SCRIPT_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    findings = await _page_secrets(client, base_url)
    findings.extend(await _sensitive_paths(client, base_url))
    return findings


async def _page_secrets(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        response = await client.get(base_url, follow_redirects=True)
    except httpx.HTTPError:
        return []
    page_hits = _scan_text(response.text)
    seen = {(label, masked) for label, _, masked in page_hits}
    findings = [_secret_finding(label, severity, masked, "page principale")
                for label, severity, masked in page_hits]
    script_urls = _script_urls(base_url, response.text)[:_MAX_SCRIPTS]
    sources = await _fetch_many(client, script_urls, limit=4)
    for url, source in zip(script_urls, sources):
        for label, severity, masked in _scan_text(source):
            if (label, masked) in seen:
                continue
            seen.add((label, masked))
            findings.append(_secret_finding(label, severity, masked, url.rsplit("/", 1)[-1]))
    return findings


async def _fetch_many(client: httpx.AsyncClient, urls: list[str], limit: int) -> list[str]:
    semaphore = asyncio.Semaphore(limit)

    async def fetch(url: str) -> str:
        async with semaphore:
            await asyncio.sleep(_DELAY_S)
            try:
                response = await client.get(url, follow_redirects=True)
            except httpx.HTTPError:
                return ""
            return response.text

    return list(await asyncio.gather(*(fetch(url) for url in urls)))


def _script_urls(base_url: str, html: str) -> list[str]:
    return [str(httpx.URL(base_url).join(src)) for src in _SCRIPT_RE.findall(html)]


def _scan_text(text: str) -> list[tuple[str, Severity, str]]:
    return [(label, severity, _mask(match.group(0)))
            for label, severity, pattern in _SECRET_PATTERNS
            for match in pattern.finditer(text)]


def find_secrets(text: str) -> list[tuple[str, Severity, str]]:
    """API publique (testée) : secrets détectés dans un texte, masqués."""
    return _scan_text(text)


def _secret_finding(label: str, severity: Severity, masked: str, source: str) -> Finding:
    return Finding(f"{_ID}-020", name, severity, f"Secret potentiel ({label}) dans {source}", masked,
                   "Révoquer la clé et la retirer du code livré (variable d'environnement côté serveur).")


def _mask(match: str) -> str:
    return match[:6] + "…" if len(match) > 6 else match


async def _sensitive_paths(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    semaphore = asyncio.Semaphore(3)

    async def probe(index: int, path: str, severity: Severity, pattern: re.Pattern[str] | None) -> Finding | None:
        async with semaphore:
            await asyncio.sleep(_DELAY_S * (index % 3))
            url = str(httpx.URL(base_url).join(path))
            try:
                response = await client.get(url, follow_redirects=False)
            except httpx.HTTPError:
                return None
            text = response.text[:4096]
            if response.status_code == 200 and plausible_content(pattern, text, response.headers):
                evidence = re.sub(r"\s+", " ", text)[:100]
                return Finding(f"{_ID}-{100 + index}", name, severity, f"'{path}' accessible publiquement",
                               evidence, "Restreindre l'accès serveur (403) et retirer ces fichiers du déploiement.")
            return None

    probes = [probe(index, path, severity, pattern) for index, (path, severity, pattern) in enumerate(_CHECKS)]
    return [finding for finding in await asyncio.gather(*probes) if finding]


def plausible_content(pattern: re.Pattern[str] | None, text: str, headers: httpx.Headers) -> bool:
    """Filtre anti-faux-positifs : les SPA renvoient leur index.html sur n'importe quel chemin."""
    if pattern is not None:
        return bool(pattern.search(text))
    return "text/html" not in headers.get("content-type", "").lower()
