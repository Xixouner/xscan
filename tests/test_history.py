import pytest

from xscan.history import delete_scan, list_scans, load_scan, result_from_dict, save_scan, slugify_target
from xscan.models import Finding, ModuleResult, ScanResult, Severity


def _result() -> ScanResult:
    finding = Finding("A-1", "headers", Severity.MEDIUM, "constat test", "preuve", "remède")
    return ScanResult(target="https://t.test", duration_s=1.5, results=[ModuleResult("headers", [finding])])


def test_slug_target():
    assert slugify_target("https://speed-elec-amberieu.com") == "speed-elec-amberieu_com"
    assert slugify_target("xixouner.com") == "xixouner_com"


def test_save_list_load_roundtrip(tmp_path):
    path = save_scan(_result(), tmp_path)
    assert path.exists() and "t_test" in path.name
    scans = list_scans(tmp_path)
    assert len(scans) == 1
    loaded = load_scan(scans[0][0])
    assert loaded.target == "https://t.test"
    assert loaded.score() == _result().score()
    assert loaded.findings()[0].title == "constat test"


def test_list_ignores_invalid_json_and_keeps_recent_first(tmp_path):
    (tmp_path / "casse.json").write_text("pas du json", encoding="utf-8")
    (tmp_path / "pas-un-scan.json").write_text('{"message": "hi"}', encoding="utf-8")
    save_scan(_result(), tmp_path)
    assert len(list_scans(tmp_path)) == 1


def test_delete_scan(tmp_path):
    path = save_scan(_result(), tmp_path)
    delete_scan(path)
    assert not path.exists()
    assert list_scans(tmp_path) == []
