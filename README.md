# Web Vulnerability Scanner

A lightweight, modular Python tool for identifying common web application
security misconfigurations. Built as a practical companion to risk
assessment work — every finding is scored using a severity-weighted model
inspired by qualitative risk matrices (similar to SLE/ALE-style reasoning
used in risk management).

> ⚠️ **Authorized use only.** Only scan systems you own or have explicit
> written permission to test. Unauthorized scanning of systems you don't
> control may be illegal in your jurisdiction. This tool sends only
> benign, non-destructive requests and is intended for education and
> authorized security assessments.

## Features

- **Security headers check** — flags missing `Content-Security-Policy`,
  `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`, insecure cookie flags, and
  information-leaking headers (`Server`, `X-Powered-By`).
- **Exposed file/path detection** — probes for common sensitive paths
  such as `.git/`, `.env`, backup files, and config leftovers.
- **Outdated JS library detection** — parses `<script>` tags and flags
  known-vulnerable versions of jQuery, AngularJS, Bootstrap, Lodash, and
  Moment.js.
- **Basic injection point probing** — submits benign markers to
  discovered forms and checks for reflected XSS or SQL error signatures.
- **SSL/TLS check** — certificate expiry, validity, and HTTP → HTTPS
  redirect enforcement.
- **Risk scoring** — aggregates findings into a weighted score and an
  overall risk level (Minimal → Critical).
- **Reports** — generates both a machine-readable JSON report and a
  styled, shareable HTML report.

## Installation

```bash
git clone https://github.com/d7mo25/web-vuln-scanner.git
cd web-vuln-scanner
pip install -r requirements.txt
```

Requires Python 3.9+.

## Usage

```bash
python cli.py --url https://example.com
```

You'll be asked to confirm you're authorized to scan the target before
the scan runs. To skip the confirmation prompt (e.g. in CI):

```bash
python cli.py --url https://example.com --yes
```

### Options

| Flag            | Description                                                        |
|-----------------|----------------------------------------------------------------------|
| `--url`         | Target URL to scan (required)                                       |
| `--skip`        | Comma-separated list of checks to skip: `headers,files,js,injection,ssl` |
| `--output-dir`  | Directory to write JSON/HTML reports (default: `./reports`)         |
| `--yes`         | Skip the interactive authorization prompt                           |

### Example

```bash
python cli.py --url https://your-own-test-site.com --skip injection
```

Reports are written to `./reports/<hostname>_report.{json,html}`.

## Testing it safely

Don't have a target to scan? Spin up a deliberately vulnerable app
locally, such as [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
or [DVWA](https://github.com/digininja/DVWA), and point the scanner at
`http://localhost:<port>`.

## Project structure

```
web-vuln-scanner/
├── scanner/
│   ├── headers.py           # Security headers check
│   ├── exposed_files.py     # Sensitive path probing
│   ├── js_libraries.py      # Outdated JS library detection
│   ├── injection_tests.py   # Benign XSS/SQLi reflection probing
│   ├── ssl_check.py         # TLS/certificate check
│   └── risk.py              # Severity-weighted risk scoring
├── report/
│   ├── generator.py         # JSON + HTML report generation
│   └── template.html        # HTML report template
├── tests/                   # Unit tests (pytest)
├── cli.py                   # CLI entry point
└── requirements.txt
```

## Running tests

```bash
pip install pytest
pytest tests/ -v
```

## Roadmap

- [ ] Async scanning for faster multi-check runs
- [ ] Expand the vulnerable JS library dataset (or pull from an OSV feed)
- [ ] Add a `--format` flag for Markdown output
- [ ] Docker image for easy CI integration



## Disclaimer

This tool is provided for educational purposes and authorized security
testing only. The author is not responsible for misuse or damage caused
by this tool. Always obtain explicit permission before scanning any
system you do not own.
