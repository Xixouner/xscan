from __future__ import annotations

import re

import httpx

_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
_HREF_RE = re.compile(r"""href=["']([^"'#]+)""", re.IGNORECASE)


def extract_script_srcs(html_text: str) -> list[str]:
    """Chemins/URLs des <script src="..."> d'une page (partagé par exposure, endpoints, sourcemaps)."""
    return _SCRIPT_SRC_RE.findall(html_text)


def extract_hrefs(html_text: str) -> list[str]:
    """Liens <a href="..."> d'une page, sans fragments (partagé par pages, redirects_open, xss_probe)."""
    return _HREF_RE.findall(html_text)


def resolve(page_url: str, target: str) -> httpx.URL:
    """Résout un href/src relatif ou absolu contre l'URL de la page."""
    return httpx.URL(page_url).join(target)


def normalize_target(url: str) -> str:
    """Normalise une cible saisie par un humain : ajoute https:// si absent.

    Lève ValueError si le schéma ou l'hôte est invalide — appelée par le CLI
    et la GUI pour que « exemple.com » fonctionne partout pareil.
    """
    candidate = url if "://" in url else f"https://{url}"
    parsed = httpx.URL(candidate)
    if parsed.scheme not in ("http", "https") or not parsed.host:
        raise ValueError(f"URL invalide : {url}")
    return str(parsed)
