from __future__ import annotations

import httpx

_USER_AGENT = "xscan/0.1 (security scan; automated; contact: site owner)"


def build_client(timeout: float = 10.0, extra_headers: dict[str, str] | None = None) -> httpx.AsyncClient:
    """Client HTTP unique : HTTP/2 activé, pas de suivi auto des redirections.

    `extra_headers` permet le scan authentifié (Cookie, Authorization...).
    Les modules décident eux-mêmes de leur politique de redirection via
    le paramètre par requête `follow_redirects`.
    """
    headers = {"User-Agent": _USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    return httpx.AsyncClient(
        timeout=timeout,
        http2=True,
        follow_redirects=False,
        headers=headers,
    )
