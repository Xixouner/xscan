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


def test_run_scan_emits_events():
    module = _module("a", [Finding("X-1", "a", Severity.MEDIUM, "constat")])
    events: list[dict] = []
    result = asyncio.run(run_scan(None, "https://t.test", modules=[module], on_event=events.append))
    assert [event["event"] for event in events] == ["scan_started", "module_started", "module_done", "scan_done"]
    assert events[2]["count"] == 1
    assert events[2]["findings"][0]["title"] == "constat"
    assert events[3]["score"] == 90
    assert result.score() == 90


def test_run_scan_emits_module_error_event():
    events: list[dict] = []
    module = _module("bad", boom=True)
    asyncio.run(run_scan(None, "https://t.test", modules=[module], on_event=events.append))
    done = [event for event in events if event["event"] == "module_done"][0]
    assert done["error"] is not None
    assert "panne réseau simulée" in done["error"]


def test_run_scan_without_event_keeps_working():
    module = _module("a", [Finding("X-2", "a", Severity.LOW, "c")])
    result = asyncio.run(run_scan(None, "https://t.test", modules=[module]))
    assert result.score() == 95
