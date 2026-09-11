"""
Report Generator
Produces JSON and HTML reports from aggregated scan results.
"""

import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = os.path.dirname(os.path.abspath(__file__))


def generate_json_report(target: str, findings: list, risk: dict, output_path: str):
    report = {
        "target": target,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "risk": risk,
        "findings": findings,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    return output_path


def generate_html_report(target: str, findings: list, risk: dict, output_path: str):
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("template.html")

    # Sort findings by severity for readability
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5))

    html = template.render(
        target=target,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        risk=risk,
        findings=sorted_findings,
    )
    with open(output_path, "w") as f:
        f.write(html)
    return output_path
