"""
Risk Scoring
Aggregates findings from all scanner modules and produces an overall
risk score, borrowing weighting concepts from qualitative risk matrices
(severity x prevalence) commonly used in risk assessment frameworks.
"""

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
    "info": 0,
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def score_findings(all_findings: list) -> dict:
    """
    Takes a flat list of finding dicts (each with a 'severity' key)
    and returns a summary: total score, risk level, and counts by severity.
    """
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    total_score = 0

    for finding in all_findings:
        severity = finding.get("severity", "info")
        if severity not in counts:
            severity = "info"
        counts[severity] += 1
        total_score += SEVERITY_WEIGHTS[severity]

    if counts["critical"] > 0:
        risk_level = "Critical"
    elif counts["high"] > 0:
        risk_level = "High"
    elif counts["medium"] > 0:
        risk_level = "Medium"
    elif counts["low"] > 0:
        risk_level = "Low"
    else:
        risk_level = "Minimal"

    return {
        "total_score": total_score,
        "risk_level": risk_level,
        "counts_by_severity": counts,
        "total_findings": len(all_findings),
    }
