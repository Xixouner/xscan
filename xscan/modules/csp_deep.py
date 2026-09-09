from __future__ import annotations

import httpx

from xscan.models import Finding, Severity

name = "csp_deep"
passive = True
DESCRIPTION = "Qualité de la Content-Security-Policy (unsafe-inline, wildcards)"

_ID = "XSCAN-CSP"


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        response = await client.get(base_url, follow_redirects=True)
    except httpx.HTTPError:
        return []
    return analyze(response.headers.get("content-security-policy", ""))


def analyze(csp_value: str) -> list[Finding]:
    """Logique pure (testée) : une CSP faible ne protège presque rien."""
    if not csp_value.strip():
        return []
    directives: dict[str, str] = {}
    for directive in csp_value.split(";"):
        parts = directive.strip().split()
        if parts:
            directives[parts[0].lower()] = " ".join(parts[1:])
    script_src = directives.get("script-src", directives.get("default-src", ""))
    findings: list[Finding] = []
    if "unsafe-inline" in script_src:
        findings.append(Finding(f"{_ID}-001", name, Severity.MEDIUM,
                                "CSP avec unsafe-inline : la protection XSS est fortement réduite",
                                f"script-src: {script_src[:60]}" if script_src else csp_value[:60],
                                "Utiliser des nonces ou des hashes au lieu de unsafe-inline."))
    if "unsafe-eval" in script_src:
        findings.append(Finding(f"{_ID}-002", name, Severity.LOW,
                                "CSP avec unsafe-eval : permet eval() et new Function()",
                                f"script-src: {script_src[:60]}" if script_src else csp_value[:60],
                                "Retirer unsafe-eval si le front le permet."))
    weak_sources = [token for token in script_src.split() if token in ("*", "http:") or token == "http:*"]
    if weak_sources:
        findings.append(Finding(f"{_ID}-003", name, Severity.MEDIUM,
                                "CSP autorisant des sources wildcard/plain-HTTP pour les scripts",
                                f"sources faibles : {', '.join(weak_sources)}",
                                "Lister explicitement les origines en https."))
    return findings
