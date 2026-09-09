from __future__ import annotations

import httpx

_USER_AGENT = "xscan/0.1 (security scan; automated; contact: site owner)"


def build_client(timeout: float = 10.0) -> httpx.AsyncClient:
    """Client HTTP unique : HTTP/2 activé, pas de suivi auto des redirections.

    Les modules décident eux-mêmes de leur politique de redirection via
    le paramètre par requête `follow_redirects`.
    """
    return httpx.AsyncClient(
        timeout=timeout,
        http2=True,
        follow_redirects=False,
        headers={"User-Agent": _USER_AGENT},
    )
