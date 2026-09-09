from __future__ import annotations

import httpx

from xscan.doh import dns_query
from xscan.models import Finding, Severity

name = "dns"
passive = True
DESCRIPTION = "Usurpation email (SPF/DMARC), CAA, DNSSEC via DNS-over-HTTPS"

_ID = "XSCAN-DNS"
_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "mail", "resend")


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    domain = httpx.URL(base_url).host
    if not domain:
        return []
    txt = await dns_query(client, domain, "TXT")
    dmarc = await dns_query(client, f"_dmarc.{domain}", "TXT")
    caa = await dns_query(client, domain, "CAA")
    ds = await dns_query(client, domain, "DS")
    dkim = await _dkim_probe(client, domain)
    return spf_findings(txt) + dmarc_findings(dmarc) + caa_findings(caa) + dnssec_findings(ds) + dkim


async def _dkim_probe(client: httpx.AsyncClient, domain: str) -> list[Finding]:
    """Sélecteurs DKIM communs : informatif seulement (l'absence n'est pas un défaut)."""
    for selector in _DKIM_SELECTORS:
        records = await dns_query(client, f"{selector}._domainkey.{domain}", "TXT")
        if any("p=" in record for record in records):
            return [Finding(f"{_ID}-006", name, Severity.INFO, f"DKIM trouvé (sélecteur {selector})",
                            f"{selector}._domainkey.{domain}", "—")]
    return []


def spf_findings(txt_records: list[str]) -> list[Finding]:
    """Logique pure (testée) : SPF absent ou permissif."""
    spf = [record for record in txt_records if record.lower().startswith("v=spf1")]
    if not spf:
        return [Finding(f"{_ID}-001", name, Severity.MEDIUM, "Aucun enregistrement SPF : emails usurpables",
                        "TXT v=spf1 absent", "Publier un SPF (ex: v=spf1 include:provider.com -all).")]
    if "+all" in spf[0]:
        return [Finding(f"{_ID}-002", name, Severity.HIGH, "SPF permissif (+all) : n'importe quel serveur peut usurper",
                        spf[0][:80], "Remplacer +all par -all.")]
    return []


def dmarc_findings(dmarc_records: list[str]) -> list[Finding]:
    """Logique pure (testée) : DMARC absent."""
    if not any("v=dmarc1" in record.lower() for record in dmarc_records):
        return [Finding(f"{_ID}-003", name, Severity.MEDIUM, "Aucun DMARC : aucun contrôle sur les emails usurpés",
                        "_dmarc TXT absent", "Publier _dmarc (v=DMARC1; p=quarantine; rua=mailto:...).")]
    return []


def caa_findings(caa_records: list[str]) -> list[Finding]:
    """CAA absent : information (tous les CA peuvent émettre pour le domaine)."""
    if not caa_records:
        return [Finding(f"{_ID}-004", name, Severity.INFO, "Pas d'enregistrement CAA (tous les CA autorisés)",
                        "CAA absent", "Restreindre les CA autorisés à émettre pour ce domaine.")]
    return []


def dnssec_findings(ds_records: list[str]) -> list[Finding]:
    """Logique pure (testée) : DNSSEC non activé."""
    if not ds_records:
        return [Finding(f"{_ID}-005", name, Severity.INFO, "DNSSEC non activé", "DS absent de la zone parente",
                        "Activer DNSSEC chez le registrar si l'usage le justifie.")]
    return []
