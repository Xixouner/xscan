from __future__ import annotations

import asyncio
import json
import shutil

import httpx

from xscan.models import Finding, Severity

name = "nuclei"
passive = False
DESCRIPTION = "Orchestration optionnelle de nuclei (si installé)"

_ID = "XSCAN-NUCLEI"
_TIMEOUT_S = 300.0
_RATE_LIMIT = 40
_SEV_MAP: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


async def run(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    if shutil.which("nuclei") is None:
        return [Finding(f"{_ID}-000", name, Severity.INFO, "nuclei non installé, orchestration ignorée",
                        "nuclei absent du PATH",
                        "Lancer `xscan install-nuclei` pour l'installer automatiquement.")]
    try:
        process = await asyncio.create_subprocess_exec(
            "nuclei", "-u", base_url, "-json", "-silent", "-nc", "-rl", str(_RATE_LIMIT), "-duc",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=_TIMEOUT_S)
    except (TimeoutError, OSError) as exc:
        return [Finding(f"{_ID}-099", name, Severity.INFO, "Exécution nuclei en échec", str(exc)[:120], "—")]
    return parse_output(stdout.decode(errors="replace"), base_url)


def parse_output(raw: str, target: str) -> list[Finding]:
    """Logique pure (testée) : lignes JSON de nuclei -> findings dédupliqués."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = event.get("info") or {}
        key = (str(event.get("template-id", "")), str(event.get("matched-at", "")))
        if key in seen:
            continue
        seen.add(key)
        severity = _SEV_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        template_id = str(event.get("template-id", "inconnu"))
        findings.append(Finding(
            f"{_ID}-001", name, severity,
            f"{template_id} : {info.get('name', 'détection nuclei')}",
            f"{event.get('matched-at', target)} — {info.get('description', '')}"[:120],
            f"Vérifier la détection nuclei « {template_id} » et appliquer le correctif associé.",
        ))
    return findings
