from __future__ import annotations

import asyncio
import time
from importlib import import_module
from types import ModuleType

import httpx

from xscan.models import ModuleResult, ScanResult


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
) -> ScanResult:
    """Exécute les modules en parallèle, agrège les résultats, ne laisse jamais
    une exception d'un module casser le scan entier."""
    chosen = modules if modules is not None else load_modules(passive_only, only)
    if passive_only:
        chosen = [module for module in chosen if module.passive]
    result = ScanResult(target=base_url)
    start = time.perf_counter()
    outcomes = await asyncio.gather(
        *(module.run(client, base_url) for module in chosen),
        return_exceptions=True,
    )
    for module, outcome in zip(chosen, outcomes):
        if isinstance(outcome, BaseException):
            result.results.append(ModuleResult(module.name, [], f"{type(outcome).__name__}: {outcome}"))
        else:
            result.results.append(ModuleResult(module.name, outcome))
    result.duration_s = round(time.perf_counter() - start, 2)
    return result
