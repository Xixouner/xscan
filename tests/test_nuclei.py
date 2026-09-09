import json

from xscan.models import Severity
from xscan.modules import nuclei


def _line(template_id: str, severity: str, matched: str = "https://t.test/x") -> str:
    return json.dumps({
        "template-id": template_id,
        "matched-at": matched,
        "info": {"name": f"détection {template_id}", "severity": severity, "description": "desc"},
    })


def test_parse_output_maps_severity_and_fields():
    findings = nuclei.parse_output(_line("cve-2021-44228", "critical"), "https://t.test")
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert "cve-2021-44228" in findings[0].title
    assert "https://t.test/x" in findings[0].evidence


def test_invalid_lines_ignored_and_duplicates_removed():
    raw = _line("a", "low") + "\nnot-json\n\n" + _line("a", "low") + "\n" + _line("b", "info")
    assert len(nuclei.parse_output(raw, "https://t.test")) == 2


def test_unknown_severity_defaults_to_info():
    findings = nuclei.parse_output(_line("x", "bizarre"), "https://t.test")
    assert findings[0].severity is Severity.INFO
