"""
Basic Injection Point Prober
Sends benign, non-destructive test strings to forms/query params and
looks for reflection or error-based signatures that suggest the input
is not being sanitized. This is a lightweight *detection* aid, not an
exploitation tool -- it never attempts to extract data or damage state.

IMPORTANT: Only run this against systems you own or are explicitly
authorized to test.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Non-destructive markers. These are designed to be safely reflected
# in output without altering application state or extracting data.
XSS_PROBE = "<vulnscan_probe>alert(1)</vulnscan_probe>"
SQLI_PROBES = ["'", "\"", "' OR '1'='1", "1' AND '1'='2"]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "pg_query()",
    "odbc_exec",
    "sqlite3.operationalerror",
    "ora-01756",
]


def _find_forms(html: str):
    soup = BeautifulSoup(html, "html.parser")
    return soup.find_all("form")


def _submit_form(base_url: str, form, payload: str, timeout: int):
    action = form.get("action") or base_url
    target_url = urljoin(base_url, action)
    method = (form.get("method") or "get").lower()

    data = {}
    for field in form.find_all(["input", "textarea"]):
        name = field.get("name")
        if not name:
            continue
        field_type = (field.get("type") or "text").lower()
        if field_type in ("submit", "button", "image", "file", "hidden"):
            data[name] = field.get("value", "")
        else:
            data[name] = payload

    try:
        if method == "post":
            return requests.post(target_url, data=data, timeout=timeout)
        return requests.get(target_url, params=data, timeout=timeout)
    except requests.exceptions.RequestException:
        return None


def check_injection_points(url: str, timeout: int = 10) -> dict:
    """
    Discover forms on the page and probe them with benign XSS/SQLi
    markers, checking whether the response reflects the marker
    unescaped or surfaces a database error signature.
    """
    findings = []

    try:
        response = requests.get(url, timeout=timeout)
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "findings": [], "forms_tested": 0}

    forms = _find_forms(response.text)

    for i, form in enumerate(forms):
        # XSS reflection check
        xss_resp = _submit_form(url, form, XSS_PROBE, timeout)
        if xss_resp is not None and XSS_PROBE in xss_resp.text:
            findings.append(
                {
                    "check": f"Possible reflected XSS in form #{i + 1}",
                    "severity": "high",
                    "description": "Unescaped input marker was reflected back in the response, "
                                    "suggesting insufficient output encoding.",
                }
            )

        # SQLi error-based check
        for probe in SQLI_PROBES:
            sqli_resp = _submit_form(url, form, probe, timeout)
            if sqli_resp is None:
                continue
            body_lower = sqli_resp.text.lower()
            if any(sig in body_lower for sig in SQL_ERROR_SIGNATURES):
                findings.append(
                    {
                        "check": f"Possible SQL injection in form #{i + 1}",
                        "severity": "critical",
                        "description": "A database error signature was returned after submitting "
                                        "a SQL metacharacter, suggesting unsanitized input reaching a query.",
                    }
                )
                break  # one confirmed finding per form is enough

    return {"findings": findings, "forms_tested": len(forms)}
