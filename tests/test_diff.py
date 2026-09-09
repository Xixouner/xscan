from xscan.diff import diff_results


def _scan(score: int, modules: list) -> dict:
    return {"target": "https://t.test", "score": score, "modules": modules}


def _module(name: str, ids: list[str]) -> dict:
    return {"name": name, "error": None,
            "findings": [{"id": i, "severity": "low", "title": f"constat {i}", "evidence": "", "remediation": ""}
                         for i in ids]}


def test_diff_added_resolved_kept_and_delta():
    old = _scan(90, [_module("headers", ["A", "B"])])
    new = _scan(95, [_module("headers", ["B", "C"])])
    report = diff_results(old, new)
    assert {finding["id"] for finding in report["added"]} == {"C"}
    assert {finding["id"] for finding in report["resolved"]} == {"A"}
    assert report["kept_count"] == 1
    assert report["delta"] == 5


def test_diff_on_empty_scans():
    report = diff_results(_scan(100, [_module("headers", [])]), _scan(100, [_module("headers", [])]))
    assert report["added"] == [] and report["resolved"] == []
    assert report["delta"] == 0


def test_diff_keeps_module_in_added_items():
    old = _scan(50, [])
    new = _scan(50, [_module("endpoints", ["X-1"])])
    added = diff_results(old, new)["added"]
    assert added[0]["module"] == "endpoints"
