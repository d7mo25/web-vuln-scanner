import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.risk import score_findings


def test_no_findings():
    result = score_findings([])
    assert result["risk_level"] == "Minimal"
    assert result["total_score"] == 0
    assert result["total_findings"] == 0


def test_critical_finding_drives_risk_level():
    findings = [
        {"severity": "low"},
        {"severity": "critical"},
    ]
    result = score_findings(findings)
    assert result["risk_level"] == "Critical"
    assert result["total_findings"] == 2
    assert result["total_score"] == 12  # 10 (critical) + 2 (low)


def test_counts_by_severity():
    findings = [
        {"severity": "high"},
        {"severity": "high"},
        {"severity": "medium"},
    ]
    result = score_findings(findings)
    assert result["counts_by_severity"]["high"] == 2
    assert result["counts_by_severity"]["medium"] == 1
    assert result["risk_level"] == "High"


def test_unknown_severity_treated_as_info():
    findings = [{"severity": "unknown"}]
    result = score_findings(findings)
    assert result["counts_by_severity"]["info"] == 1
    assert result["risk_level"] == "Minimal"
