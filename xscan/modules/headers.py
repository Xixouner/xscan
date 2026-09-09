from __future__ import annotations

import re

import httpx

from xscan.models import Finding, Severity

name = "headers"
passive = True
DESCRIPTION = "En-têtes de sécurité HTTP, cookies et CORS"

_ID = "XSCAN-HEADERS"
_HSTS_MIN_MAX_AGE = 15552000

_MISSING = [
    ("content-security-policy", f"{_ID}-001", Severity.MEDIUM, "Content-Security-Policy absente",
     "Définir une CSP (ex: default-src 'self') pour limiter l'impact d'une XSS."),
    ("strict-transport-security", f"{_ID}-002", Severity.MEDIUM, "HSTS absente",
     "Ajouter Strict-Transport-Security: max-age=15552000; includeSubDomains."),
    ("x-content-type-options", f"{_ID}-003", Severity.LOW, "X-Content-Type-Options absente",
     "Ajouter X-Content-Type-Options: nosniff."),
    ("x-frame-options", f"{_ID}-004", Severity.LOW, "Protection clickjacking absente",
     "Ajouter X-Frame-Options: DENY ou CSP frame-ancestors 'none'."),
    ("referrer-policy", f"{_ID}-005", Severity.LOW, "Referrer-Policy absente",
     "Ajouter Referrer-Policy: strict-origin-when-cross-origin."),
    ("permissions-policy", f"{_ID}-006", Severity.INFO, "Permissions-Policy absente",
     "Définir explicitement les permissions (camera, geolocation, ...)."),
]


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    response = await client.get(base_url, follow_redirects=True)
    return evaluate(response)


def evaluate(response: httpx.Response) -> list[Finding]:
    """Logique pure (testable sans réseau) : analyse la réponse finale."""
    headers = response.headers
    findings = [
        Finding(fid, name, severity, title, f"en-tête '{header}' absent", remediation)
        for header, fid, severity, title, remediation in _MISSING
        if header not in headers
    ]
    findings.extend(_hsts_policy(headers.get("strict-transport-security", "")))
    findings.extend(_cookies(headers.get_list("set-cookie")))
    findings.extend(_cors(headers.get("access-control-allow-origin", "")))
    findings.extend(_banners(headers.get("server", ""), headers.get("x-powered-by", "")))
    return findings


def _hsts_policy(value: str) -> list[Finding]:
    match = re.search(r"max-age=(\d+)", value)
    if match and int(match.group(1)) < _HSTS_MIN_MAX_AGE:
        return [Finding(f"{_ID}-007", name, Severity.LOW, "HSTS avec max-age trop court", value,
                        f"Utiliser max-age >= {_HSTS_MIN_MAX_AGE}.")]
    return []


def _cookies(cookies: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for cookie in cookies:
        lower = cookie.lower()
        missing = [flag for flag in ("secure", "httponly") if flag not in lower]
        if "samesite" not in lower:
            missing.append("samesite")
        if missing:
            cookie_name = cookie.split("=")[0].strip()
            findings.append(Finding(
                f"{_ID}-008", name, Severity.LOW,
                f"Cookie '{cookie_name}' sans : {', '.join(missing)}",
                cookie[:80], "Ajouter Secure, HttpOnly et SameSite aux cookies de session."))
    return findings


def _cors(origin: str) -> list[Finding]:
    if origin == "*":
        return [Finding(f"{_ID}-009", name, Severity.MEDIUM, "CORS ouvert à toutes les origines",
                        "access-control-allow-origin: *",
                        "Restreindre l'origine autorisée; '*' n'est acceptable que pour des API 100% publiques.")]
    return []


def _banners(server: str, powered_by: str) -> list[Finding]:
    findings: list[Finding] = []
    if server:
        findings.append(Finding(f"{_ID}-010", name, Severity.INFO, "Bannière serveur révélée", server,
                                "Masquer ou généraliser l'en-tête Server."))
    if powered_by:
        findings.append(Finding(f"{_ID}-011", name, Severity.LOW, "Technologie révélée via X-Powered-By", powered_by,
                                "Supprimer l'en-tête X-Powered-By."))
    return findings
