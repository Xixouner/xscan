from __future__ import annotations

from xscan.modules import (
    endpoints,
    exposure,
    fingerprint,
    forms,
    headers,
    subdomains,
    transport,
)

ALL_MODULES = [transport, headers, fingerprint, subdomains, endpoints, forms, exposure]
