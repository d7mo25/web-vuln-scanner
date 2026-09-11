"""
Outdated JavaScript Library Detector
Parses <script> tags on a page and flags known-vulnerable library versions.
"""

import re
import requests
from bs4 import BeautifulSoup

# Minimal known-vulnerable version ranges for common libraries.
# Format: library -> (safe_min_version, severity, cve_note)
# This is intentionally a small, illustrative dataset -- extend as needed.
VULNERABLE_LIBRARIES = {
    "jquery": {
        "safe_min_version": (3, 5, 0),
        "severity": "medium",
        "note": "jQuery < 3.5.0 has known XSS vulnerabilities (e.g., CVE-2020-11022/11023).",
    },
    "angular": {
        "safe_min_version": (1, 8, 0),
        "severity": "medium",
        "note": "AngularJS < 1.8.0 has known sandbox-bypass XSS vulnerabilities.",
    },
    "bootstrap": {
        "safe_min_version": (4, 3, 1),
        "severity": "low",
        "note": "Bootstrap < 4.3.1 has known XSS vulnerabilities in tooltip/popover/scrollspy.",
    },
    "lodash": {
        "safe_min_version": (4, 17, 21),
        "severity": "high",
        "note": "Lodash < 4.17.21 has known prototype pollution vulnerabilities.",
    },
    "moment": {
        "safe_min_version": (2, 29, 4),
        "severity": "medium",
        "note": "Moment.js < 2.29.4 has a known ReDoS vulnerability.",
    },
}

# Matches library-name@version or library-name.version in a script src, e.g.
# "jquery-3.4.1.min.js" or "jquery/3.4.1/jquery.min.js"
VERSION_PATTERN = re.compile(r"([a-zA-Z.]+)[/.-](\d+)\.(\d+)\.(\d+)")


def _parse_version(major, minor, patch):
    return (int(major), int(minor), int(patch))


def check_js_libraries(url: str, timeout: int = 10) -> dict:
    """
    Fetch a page, extract script src attributes, and check detected
    library versions against a small known-vulnerable dataset.
    """
    try:
        response = requests.get(url, timeout=timeout)
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "findings": [], "libraries_detected": []}

    soup = BeautifulSoup(response.text, "html.parser")
    scripts = soup.find_all("script", src=True)

    findings = []
    detected = []

    for script in scripts:
        src = script["src"]
        match = VERSION_PATTERN.search(src)
        if not match:
            continue

        lib_raw, major, minor, patch = match.groups()
        lib_name = lib_raw.strip(".").lower()

        # Normalize common variants (e.g. "jquery.min" -> "jquery")
        for known_lib in VULNERABLE_LIBRARIES:
            if known_lib in lib_name:
                version = _parse_version(major, minor, patch)
                safe_min = VULNERABLE_LIBRARIES[known_lib]["safe_min_version"]
                detected.append({"library": known_lib, "version": ".".join([major, minor, patch]), "src": src})

                if version < safe_min:
                    findings.append(
                        {
                            "check": f"Outdated {known_lib} ({'.'.join([major, minor, patch])})",
                            "severity": VULNERABLE_LIBRARIES[known_lib]["severity"],
                            "description": VULNERABLE_LIBRARIES[known_lib]["note"],
                            "source": src,
                        }
                    )
                break

    return {"findings": findings, "libraries_detected": detected}
