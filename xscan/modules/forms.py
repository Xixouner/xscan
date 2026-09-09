from __future__ import annotations

from html.parser import HTMLParser
from typing import TypedDict

import httpx

from xscan.models import Finding, Severity

name = "forms"
passive = True
DESCRIPTION = "Formulaires : CSRF, méthode, password, action cross-origin"

_ID = "XSCAN-FORMS"
_CSRF_HINTS = ("csrf", "token", "authenticity", "nonce")


class Form(TypedDict):
    attrs: dict[str, str]
    inputs: list[dict[str, str]]


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[Form] = []
        self._current: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "form":
            self._current = {"attrs": {k or "": v or "" for k, v in attrs}, "inputs": []}
        elif tag == "input" and self._current is not None:
            self._current["inputs"].append({k or "": v or "" for k, v in attrs})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def close(self) -> None:
        super().close()
        if self._current is not None:  # form non fermé proprement dans le HTML
            self.forms.append(self._current)
            self._current = None


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    try:
        page = await client.get(base_url, follow_redirects=True)
    except httpx.HTTPError:
        return []
    return analyze_forms(page.text, str(page.url))


def analyze_forms(html: str, page_url: str) -> list[Finding]:
    """Logique pure (testée) : heuristiques sur les formulaires de la page."""
    parser = _FormParser()
    parser.feed(html)
    parser.close()
    page = httpx.URL(page_url)
    findings: list[Finding] = []
    for form in parser.forms:
        findings.extend(_form_findings(form, page))
    return findings


def _form_findings(form: Form, page: httpx.URL) -> list[Finding]:
    inputs = form["inputs"]
    has_password = any(i.get("type", "").lower() == "password" for i in inputs)
    method = form["attrs"].get("method", "get").lower()
    action = form["attrs"].get("action", "") or ""
    findings: list[Finding] = []
    if has_password and page.scheme == "http":
        findings.append(Finding(f"{_ID}-001", name, Severity.HIGH, "Mot de passe soumis sans HTTPS",
                                action or "(même page)", "Servir la page en HTTPS."))
    if has_password and method == "get":
        findings.append(Finding(f"{_ID}-002", name, Severity.MEDIUM, "Mot de passe soumis en GET (finira dans l'URL)",
                                action or "(même page)", "Passer le formulaire en POST."))
    if method == "post" and not _has_csrf(inputs):
        findings.append(Finding(f"{_ID}-003", name, Severity.LOW, "POST sans jeton CSRF visible dans le HTML",
                                action or "(même page)",
                                "Peut être géré en en-tête (X-CSRF-Token); sinon ajouter un champ caché."))
    if has_password and action.startswith(("http://", "https://")) and httpx.URL(action).host != page.host:
        findings.append(Finding(f"{_ID}-004", name, Severity.MEDIUM, "Formulaire mot de passe envoyé vers un domaine tiers",
                                action, "Vérifier la légitimité de cette action cross-origin."))
    return findings


def _has_csrf(inputs: list[dict[str, str]]) -> bool:
    return any(
        any(hint in i.get("name", "").lower() or hint in i.get("type", "").lower() for hint in _CSRF_HINTS)
        for i in inputs
    )
