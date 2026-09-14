from __future__ import annotations

import asyncio
import time
from importlib import import_module
from types import ModuleType

import httpx

from xscan.models import Finding, ModuleResult, ScanResult, Severity


def _serialize(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "severity": finding.severity.value,
        "title": finding.title,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
    }


def load_modules(passive_only: bool, only: list[str] | None = None) -> list[ModuleType]:
    registry = import_module("xscan.modules")
    chosen = registry.ALL_MODULES
    if only:
        known = {module.name for module in chosen}
        unknown = [name_value for name_value in only if name_value not in known]
        if unknown:
            raise ValueError(f"modules inconnus : {', '.join(unknown)} (disponibles : {', '.join(m.name for m in chosen)})")
        chosen = [module for module in chosen if module.name in only]
    return [module for module in chosen if not (passive_only and not module.passive)]


async def run_scan(
    client: httpx.AsyncClient,
    base_url: str,
    modules: list[ModuleType] | None = None,
    passive_only: bool = False,
    only: list[str] | None = None,
    on_event=None,
) -> ScanResult:
    """Exécute les modules en parallèle, agrège les résultats, ne laisse jamais
    une exception d'un module casser le scan entier.

    `on_event` (optionnel) reçoit des dictionnaires d'événements pour suivre le
    scan en temps réel — c'est le pont vers une GUI :
    scan_started -> (module_started -> module_done)* -> scan_done.
    """
    chosen = modules if modules is not None else load_modules(passive_only, only)
    if passive_only:
        chosen = [module for module in chosen if module.passive]
    result = ScanResult(target=base_url)
    start = time.perf_counter()
    if on_event:
        on_event({"event": "scan_started", "target": base_url, "modules": [m.name for m in chosen]})

    async def run_module(module: ModuleType) -> list[Finding]:
        if on_event:
            on_event({"event": "module_started", "module": module.name})
        try:
            findings = await module.run(client, base_url)
        except Exception as exc:
            if on_event:
                on_event({"event": "module_done", "module": module.name, "count": 0,
                          "findings": [], "error": f"{type(exc).__name__}: {exc}"[:120]})
            raise
        if on_event:
            on_event({"event": "module_done", "module": module.name, "count": len(findings),
                      "findings": [_serialize(finding) for finding in findings], "error": None})
        return findings

    outcomes = await asyncio.gather(*(run_module(module) for module in chosen), return_exceptions=True)
    for module, outcome in zip(chosen, outcomes):
        if isinstance(outcome, BaseException):
            result.results.append(ModuleResult(module.name, [], f"{type(outcome).__name__}: {outcome}"))
        else:
            result.results.append(ModuleResult(module.name, outcome))
    result.duration_s = round(time.perf_counter() - start, 2)
    if on_event:
        counts: dict[str, int] = {}
        for finding in result.findings():
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        on_event({"event": "scan_done", "target": base_url, "score": result.score(),
                  "duration_s": result.duration_s,
                  "summary": {severity.value: counts.get(severity.value, 0) for severity in Severity}})
    return result
