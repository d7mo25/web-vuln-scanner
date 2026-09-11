"""
Security Headers Checker
Checks HTTP response headers for common security misconfigurations.
"""

import requests

# Headers considered essential for web security, with guidance on missing them
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "high",
        "description": "Missing CSP header allows a wider range of XSS and data injection attacks.",
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "Missing HSTS allows the site to be accessed over insecure HTTP, enabling downgrade/MITM attacks.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Missing X-Frame-Options makes the site vulnerable to clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "Missing X-Content-Type-Options allows MIME-sniffing attacks.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Missing Referrer-Policy may leak sensitive URL data to third parties.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Missing Permissions-Policy leaves browser feature access (camera, geolocation, etc.) unrestricted.",
    },
}

# Headers that should NOT be present because they leak information
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def check_headers(url: str, timeout: int = 10) -> dict:
    """
    Fetch a URL and evaluate its response headers for security issues.

    Returns a dict with:
      - findings: list of finding dicts (name, severity, description)
      - raw_headers: the full header dict returned by the server
    """
    findings = []

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "findings": [], "raw_headers": {}}

    headers = response.headers

    # Check for missing protective headers
    for header_name, meta in SECURITY_HEADERS.items():
        if header_name not in headers:
            findings.append(
                {
                    "check": f"Missing {header_name}",
                    "severity": meta["severity"],
                    "description": meta["description"],
                }
            )

    # Check for information-leaking headers
    for header_name in INFO_LEAK_HEADERS:
        if header_name in headers:
            findings.append(
                {
                    "check": f"Information disclosure via {header_name}",
                    "severity": "low",
                    "description": f"Server exposes '{header_name}: {headers[header_name]}', "
                                    f"which can help attackers fingerprint your stack.",
                }
            )

    # Check cookies for Secure / HttpOnly flags
    set_cookie_headers = response.raw.headers.get_all("Set-Cookie") if response.raw.headers else None
    if set_cookie_headers:
        for cookie in set_cookie_headers:
            cookie_lower = cookie.lower()
            if "secure" not in cookie_lower:
                findings.append(
                    {
                        "check": "Cookie missing Secure flag",
                        "severity": "medium",
                        "description": f"Cookie set without 'Secure' flag: {cookie.split(';')[0]}",
                    }
                )
            if "httponly" not in cookie_lower:
                findings.append(
                    {
                        "check": "Cookie missing HttpOnly flag",
                        "severity": "medium",
                        "description": f"Cookie set without 'HttpOnly' flag, "
                                        f"readable by client-side JS: {cookie.split(';')[0]}",
                    }
                )

    return {
        "findings": findings,
        "raw_headers": dict(headers),
        "status_code": response.status_code,
    }
