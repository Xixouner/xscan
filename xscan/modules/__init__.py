from __future__ import annotations

from xscan.modules import (
    csp_deep,
    dns,
    endpoints,
    exposure,
    fingerprint,
    forms,
    headers,
    httpdeep,
    nuclei,
    pages,
    ports,
    redirects_open,
    sri,
    subdomains,
    takeover,
    tls_deep,
    transport,
    waf,
)

ALL_MODULES = [
    transport, headers, fingerprint, dns, subdomains, sri, endpoints, forms,
    exposure, tls_deep, httpdeep, ports, waf, csp_deep, pages, takeover,
    redirects_open, nuclei,
]
