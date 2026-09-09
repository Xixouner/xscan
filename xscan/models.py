from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    """Constat unique, avec ID stable pour suivi dans le temps."""

    id: str
    module: str
    severity: Severity
    title: str
    evidence: str = ""
    remediation: str = ""


@dataclass
class ModuleResult:
    module: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


_DEDUCTIONS: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
}


@dataclass
class ScanResult:
    target: str
    duration_s: float = 0.0
    results: list[ModuleResult] = field(default_factory=list)

    def findings(self) -> list[Finding]:
        return [finding for module_result in self.results for finding in module_result.findings]

    def score(self) -> int:
        total = sum(_DEDUCTIONS[finding.severity] for finding in self.findings())
        return max(0, 100 - total)
