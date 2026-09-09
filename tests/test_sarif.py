from xscan.models import Finding, ModuleResult, ScanResult, Severity
from xscan.sarif import to_sarif


def _result() -> ScanResult:
    findings = [
        Finding("A-1", "mod", Severity.HIGH, "Constat haut", "preuve", "corriger"),
        Finding("B-1", "mod", Severity.INFO, "Constat info", "preuve", "—"),
        Finding("A-1", "other", Severity.HIGH, "Constat haut", "autre preuve", "corriger"),
    ]
    return ScanResult(target="https://t.test", results=[ModuleResult("mod", findings[:2]), ModuleResult("other", [findings[2]])])


def test_sarif_structure_valid():
    sarif = to_sarif(_result())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "xscan"
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert rule_ids == ["A-1", "B-1"]  # règles dédupliquées


def test_sarif_severity_mapping():
    sarif = to_sarif(_result())
    levels = {result["ruleId"]: result["level"] for result in sarif["runs"][0]["results"]}
    assert levels["A-1"] == "error"  # high
    assert levels["B-1"] == "note"  # info


def test_sarif_results_count_all_findings():
    sarif = to_sarif(_result())
    assert len(sarif["runs"][0]["results"]) == 3  # même règle sur 2 modules = 2 résultats
