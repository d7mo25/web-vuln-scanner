#!/usr/bin/env python3
"""
Web Vulnerability Scanner - CLI

Usage:
    python cli.py --url https://example.com
    python cli.py --url https://example.com --skip injection,ssl
    python cli.py --url https://example.com --output-dir ./reports

For authorized security testing and educational use only. Do not scan
targets you do not own or do not have explicit permission to test.
"""

import argparse
import os
import sys
from urllib.parse import urlparse

from scanner.headers import check_headers
from scanner.exposed_files import check_exposed_files
from scanner.js_libraries import check_js_libraries
from scanner.injection_tests import check_injection_points
from scanner.ssl_check import check_ssl
from scanner.risk import score_findings
from report.generator import generate_json_report, generate_html_report

CHECKS = {
    "headers": check_headers,
    "files": check_exposed_files,
    "js": check_js_libraries,
    "injection": check_injection_points,
    "ssl": check_ssl,
}

SEVERITY_COLORS = {
    "critical": "\033[91m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


BANNER = r"""
 __        __   _        __     __      _        ____
 \ \      / /__| |__     \ \   / /   _  | |_ __  / ___|  ___ __ _ _ __
  \ \ /\ / / _ \ '_ \     \ \ / / | | | | '_ \| |     / __/ _` | '_ \
   \ V  V /  __/ |_) |     \ V /| |_| | | | | | |___| (_| (_| | | | |
    \_/\_/ \___|_.__/       \_/  \__,_|_|_| |_|\____\___\__,_|_| |_|
"""


def print_banner():
    print(BOLD + BANNER + RESET)
    print("  A lightweight web vulnerability scanner")
    print("  For authorized security testing only.\n")


def confirm_authorization(url: str) -> bool:
    print(f"You are about to scan: {BOLD}{url}{RESET}")
    answer = input("Do you own this target or have explicit written authorization to test it? [y/N]: ")
    return answer.strip().lower() == "y"


def run_scan(url: str, skip: set) -> list:
    all_findings = []

    for name, check_fn in CHECKS.items():
        if name in skip:
            print(f"  [skip] {name}")
            continue

        print(f"  [*] Running {name} check...")
        try:
            result = check_fn(url)
        except Exception as e:
            print(f"  [!] {name} check failed: {e}")
            continue

        if result.get("error"):
            print(f"  [!] {name} check error: {result['error']}")
            continue

        findings = result.get("findings", [])
        for f in findings:
            f["module"] = name
        all_findings.extend(findings)
        print(f"      -> {len(findings)} finding(s)")

    return all_findings


def print_summary(findings: list, risk: dict):
    print("\n" + BOLD + "=" * 60 + RESET)
    print(BOLD + "SCAN SUMMARY" + RESET)
    print("=" * 60)
    print(f"Total findings: {risk['total_findings']}")
    print(f"Risk score:     {risk['total_score']}")
    print(f"Risk level:     {risk['risk_level']}")
    print()

    for f in sorted(findings, key=lambda x: x.get("severity", "info")):
        color = SEVERITY_COLORS.get(f.get("severity", "info"), "")
        print(f"{color}[{f.get('severity', 'info').upper()}]{RESET} {f['check']}")
        print(f"    {f['description']}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL, e.g. https://example.com")
    parser.add_argument(
        "--skip",
        default="",
        help="Comma-separated checks to skip: headers,files,js,injection,ssl",
    )
    parser.add_argument("--output-dir", default="./reports", help="Directory for JSON/HTML reports")
    parser.add_argument("--yes", action="store_true", help="Skip the authorization confirmation prompt")
    args = parser.parse_args()

    print_banner()

    parsed = urlparse(args.url)
    if not parsed.scheme:
        print("Error: URL must include a scheme, e.g. https://example.com")
        sys.exit(1)

    if not args.yes and not confirm_authorization(args.url):
        print("Authorization not confirmed. Exiting.")
        sys.exit(1)

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}

    print(f"\nScanning {args.url} ...\n")
    findings = run_scan(args.url, skip)
    risk = score_findings(findings)

    print_summary(findings, risk)

    os.makedirs(args.output_dir, exist_ok=True)
    host = parsed.hostname or "target"
    json_path = os.path.join(args.output_dir, f"{host}_report.json")
    html_path = os.path.join(args.output_dir, f"{host}_report.html")

    generate_json_report(args.url, findings, risk, json_path)
    generate_html_report(args.url, findings, risk, html_path)

    print(f"Reports written to:\n  {json_path}\n  {html_path}")


if __name__ == "__main__":
    main()
