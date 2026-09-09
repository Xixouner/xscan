from __future__ import annotations

from xscan.modules import (
    csp_deep,
    dns,
    endpoints,
    exposure,
    fingerprint,
    forms,
    graphql,
    headers,
    httpdeep,
    nuclei,
    pages,
    ports,
    privacy,
    redirects_open,
    robots,
    sourcemaps,
    sri,
    subdomains,
    takeover,
    tls_deep,
    transport,
    waf,
    xsleaks,
    xss_probe,
)

ALL_MODULES = [
    transport, headers, fingerprint, dns, subdomains, sri, endpoints, forms,
    exposure, tls_deep, httpdeep, ports, waf, csp_deep, pages, takeover,
    redirects_open, sourcemaps, xsleaks, privacy, robots, graphql, xss_probe, nuclei,
]
