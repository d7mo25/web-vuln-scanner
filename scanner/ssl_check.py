"""
SSL/TLS Checker
Checks certificate validity/expiry and whether the site forces HTTPS.
"""

import ssl
import socket
import requests
from datetime import datetime
from urllib.parse import urlparse


def _get_cert_info(hostname: str, port: int = 443, timeout: int = 8):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            return ssock.getpeercert()


def check_ssl(url: str, timeout: int = 8) -> dict:
    """
    Checks:
      - Whether the site redirects HTTP -> HTTPS
      - Certificate expiry
      - Basic cert validity (via ssl's default verification)
    """
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.path  # handle bare domains

    if not hostname:
        return {"error": "Could not parse hostname from URL", "findings": []}

    # 1. Check if HTTP redirects to HTTPS
    try:
        http_url = f"http://{hostname}"
        resp = requests.get(http_url, timeout=timeout, allow_redirects=True)
        if not resp.url.startswith("https://"):
            findings.append(
                {
                    "check": "HTTP not redirected to HTTPS",
                    "severity": "high",
                    "description": "Site is reachable over plain HTTP without a redirect to HTTPS, "
                                    "exposing traffic to interception.",
                }
            )
    except requests.exceptions.RequestException:
        pass  # HTTP may simply be closed, which is fine

    # 2. Check certificate validity + expiry
    try:
        cert = _get_cert_info(hostname, timeout=timeout)
        not_after = cert.get("notAfter")
        if not_after:
            expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_date - datetime.utcnow()).days
            if days_left < 0:
                findings.append(
                    {
                        "check": "SSL certificate expired",
                        "severity": "critical",
                        "description": f"Certificate expired on {expiry_date.date()}.",
                    }
                )
            elif days_left < 14:
                findings.append(
                    {
                        "check": "SSL certificate expiring soon",
                        "severity": "medium",
                        "description": f"Certificate expires in {days_left} day(s), on {expiry_date.date()}.",
                    }
                )
    except ssl.SSLCertVerificationError as e:
        findings.append(
            {
                "check": "SSL certificate validation failed",
                "severity": "critical",
                "description": f"Certificate could not be verified: {e}",
            }
        )
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        findings.append(
            {
                "check": "Could not establish SSL connection",
                "severity": "info",
                "description": f"{e}",
            }
        )

    return {"findings": findings}
