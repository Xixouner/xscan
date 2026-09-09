from __future__ import annotations

from xscan import __version__
from xscan.models import ScanResult

_LEVELS = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}


def to_sarif(result: ScanResult) -> dict:
    """Logique pure (testée) : rapport SARIF 2.1.0 pour GitHub Code Scanning."""
    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: set[str] = set()
    for module_result in result.results:
        for finding in module_result.findings:
            if finding.id not in seen_rules:
                seen_rules.add(finding.id)
                rules.append({"id": finding.id, "shortDescription": {"text": finding.title}})
            results.append({
                "ruleId": finding.id,
                "level": _LEVELS[finding.severity.value],
                "message": {"text": f"{finding.title} — {finding.evidence}"[:300]},
                "properties": {
                    "module": module_result.module,
                    "severity": finding.severity.value,
                    "remediation": finding.remediation,
                },
            })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "xscan", "version": __version__,
                                "informationUri": "https://github.com/Xixouner/xscan", "rules": rules}},
            "results": results,
        }],
    }
