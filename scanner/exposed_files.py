"""
Exposed Files & Paths Checker
Probes common sensitive paths to see if they're publicly accessible.
"""

import requests
from urllib.parse import urljoin

# Path -> (severity, description)
SENSITIVE_PATHS = {
    ".git/config": ("critical", "Exposed .git directory can leak full source code history."),
    ".git/HEAD": ("critical", "Exposed .git directory can leak full source code history."),
    ".env": ("critical", "Exposed .env file often contains API keys, DB credentials, and secrets."),
    ".env.local": ("critical", "Exposed .env.local file often contains secrets."),
    "config.php.bak": ("high", "Backup config file may expose database credentials."),
    "wp-config.php.bak": ("high", "Backup WordPress config may expose database credentials."),
    "backup.zip": ("high", "Publicly accessible backup archive may contain sensitive data."),
    "backup.sql": ("high", "Publicly accessible database dump."),
    "database.sql": ("high", "Publicly accessible database dump."),
    ".htaccess": ("medium", "Exposed .htaccess can reveal server configuration/rewrite rules."),
    "phpinfo.php": ("high", "phpinfo() page exposes detailed server configuration."),
    "admin/": ("low", "Admin panel is publicly reachable; ensure it's protected."),
    "administrator/": ("low", "Admin panel is publicly reachable; ensure it's protected."),
    ".DS_Store": ("low", "Exposed .DS_Store can leak directory structure."),
    "web.config": ("medium", "Exposed web.config may reveal IIS/ASP.NET configuration."),
    "docker-compose.yml": ("high", "Exposed docker-compose.yml may reveal internal architecture and secrets."),
    "id_rsa": ("critical", "Exposed private SSH key."),
    ".well-known/security.txt": ("info", "security.txt found (informational, not a vulnerability)."),
}


def check_exposed_files(base_url: str, timeout: int = 8) -> dict:
    """
    Check a list of common sensitive paths under base_url.

    Returns a dict with a list of findings for paths that returned
    an HTTP 200 (i.e., appear to be accessible).
    """
    if not base_url.endswith("/"):
        base_url += "/"

    findings = []
    checked = 0

    for path, (severity, description) in SENSITIVE_PATHS.items():
        full_url = urljoin(base_url, path)
        checked += 1
        try:
            resp = requests.get(full_url, timeout=timeout, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue

        # Treat 200 as "exposed". Some servers return 200 with a custom
        # error page, so we do a lightweight sanity check on content length.
        if resp.status_code == 200 and len(resp.content) > 0:
            findings.append(
                {
                    "check": f"Exposed path: /{path}",
                    "severity": severity,
                    "description": description,
                    "url": full_url,
                }
            )

    return {"findings": findings, "paths_checked": checked}
