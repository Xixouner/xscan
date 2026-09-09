import asyncio
from types import SimpleNamespace

from xscan.models import Finding, Severity
from xscan.runner import run_scan


def _module(name_value: str, findings=None, boom: bool = False):
    async def run(client, base_url):
        if boom:
            raise RuntimeError("panne réseau simulée")
        return findings or []

    return SimpleNamespace(name=name_value, passive=True, run=run)


def test_run_scan_aggregates_and_scores():
    module = _module("a", [Finding("X-1", "a", Severity.MEDIUM, "constat test")])
    result = asyncio.run(run_scan(None, "https://t.test", modules=[module]))
    assert result.results[0].module == "a"
    assert result.score() == 90


def test_module_error_is_captured_not_fatal():
    module = _module("bad", boom=True)
    result = asyncio.run(run_scan(None, "https://t.test", modules=[module]))
    assert result.results[0].error is not None
    assert "panne réseau simulée" in result.results[0].error


def test_passive_only_filters_active_modules():
    active = _module("actif")
    active.passive = False
    result = asyncio.run(run_scan(None, "https://t.test", modules=[active], passive_only=True))
    assert result.results == []
