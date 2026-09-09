from __future__ import annotations

from xscan.modules import (
    dns,
    endpoints,
    exposure,
    fingerprint,
    forms,
    headers,
    httpdeep,
    nuclei,
    ports,
    sri,
    subdomains,
    tls_deep,
    transport,
)

ALL_MODULES = [transport, headers, fingerprint, dns, subdomains, sri, endpoints, forms, exposure, tls_deep, httpdeep, ports, nuclei]
