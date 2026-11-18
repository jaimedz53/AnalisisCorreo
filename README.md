# mxray

[![CI](https://github.com/jaimedz53/AnalisisCorreo/actions/workflows/ci.yml/badge.svg)](https://github.com/jaimedz53/AnalisisCorreo/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**X-ray the email setup of any domain.** `mxray` detects who hosts a domain's email
(Google, Microsoft 365, Mimecast...) and audits the DNS records that decide whether its
email lands in the inbox or in spam: **MX, SPF, DKIM, DMARC and MTA-STS**.

It works as a **CLI**, a **Python library** and a **REST API**.

```console
$ mxray check github.com

github.com  provider: Microsoft 365 (mailbox)  score: 100/100  risk: low

 Check     Status  Details
 MX        OK      1 MX record(s) found.
 SPF       OK      Valid SPF (~all, 10/10 DNS lookups).
 DMARC     OK      DMARC policy: quarantine.
 DKIM      OK      DKIM key published for selector(s): google, selector1, k1, k2, s1, s2.
 MTA-STS   INFO    MTA-STS not configured (optional, recommended).
```

> Fun fact from that output: GitHub's SPF sits at exactly **10/10 DNS lookups**. One more
> `include:` and receivers would start treating it as a permanent error.

## Why

Since 2024 Google, Yahoo and Microsoft reject or junk bulk email from domains without
proper SPF, DKIM and DMARC. When you send transactional or marketing email to thousands
of recipients, it pays to know **which provider each recipient uses** (each one filters
differently) and **whether your own domain is correctly authenticated**.

This project grew out of a tool I built professionally to adapt sending strategies per
mail provider. This is a clean-room, open source rewrite.

## Features

- **Provider detection** from MX records: 20+ mailbox providers and security gateways.
- **SPF**: missing / duplicated records, `+all` / `?all`, and **recursive DNS lookup
  counting** against the 10-lookup limit (the most common silent SPF failure).
- **DMARC**: policy (`none` / `quarantine` / `reject`), `pct`, reporting (`rua`) and
  policy inheritance from the parent domain (`sp`).
- **DKIM**: probes common selectors (Google, Microsoft 365, Mailchimp, SendGrid...).
- **MTA-STS** detection.
- **0-100 score** and risk level per domain.
- **Batch mode** for CSV / text files of emails, with concurrent lookups, de-duplication
  per domain, provider breakdown and CSV export.
- `--fail-under` exit code to use it as a **CI check** for your own domains.

## Installation

```bash
pip install "git+https://github.com/jaimedz53/AnalisisCorreo"          # CLI + library
pip install "mxray[api] @ git+https://github.com/jaimedz53/AnalisisCorreo"  # + REST API
```

## Usage

### CLI

```bash
mxray check example.com             # pretty report
mxray check jane@example.com --json # accepts emails and URLs too
mxray check example.com --fail-under 80   # exit 1 if score < 80

mxray batch customers.csv --column email -o report.csv
mxray batch domains.txt --workers 16
```

`batch` prints a table per domain and a breakdown of inputs per provider:

```text
            Inputs per provider
 Provider                    Inputs      %
 Google Workspace / Gmail      5120   51.2
 Outlook.com / Hotmail         2210   22.1
 Microsoft 365                 1430   14.3
 ...
```

### Library

```python
from mxray import audit_domain

report = audit_domain("example.com")
print(report.provider, report.score, report.risk)
for check in report.checks:
    print(check.name, check.status.value, check.message)
```

### REST API

```bash
mxray serve            # http://127.0.0.1:8000/docs
```

| Method | Endpoint             | Description                         |
| ------ | -------------------- | ----------------------------------- |
| GET    | `/health`            | Health check                        |
| GET    | `/domains/{domain}`  | Audit one domain                    |
| POST   | `/audit`             | Audit up to 100 domains/emails      |

## Scoring

| Check   | Weight | OK   | WARN / INFO | FAIL |
| ------- | -----: | ---- | ----------- | ---- |
| MX      | 20     | 100% | 50%         | 0%   |
| SPF     | 30     | 100% | 50%         | 0%   |
| DMARC   | 35     | 100% | 50%         | 0%   |
| DKIM    | 15     | 100% | 50%         | 0%   |
| MTA-STS | 0 (informational) | | |      |

Risk: **low** ≥ 80, **medium** ≥ 50, **high** < 50.

## Architecture

```
src/mxray/
├── resolver.py   # DNS behind a small Protocol (real: dnspython, tests: in-memory fake)
├── providers.py  # MX host -> provider rules
├── checks.py     # pure functions: one check each, return a Check
├── audit.py      # orchestration, scoring, concurrency
├── cli.py        # Typer + Rich
└── api.py        # FastAPI
```

Checks never call the network directly: they receive a `Resolver`. That keeps them pure
and lets the whole test suite run **offline and deterministically** with a fake resolver.

## Development

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[api,dev]"
pytest
ruff check . && ruff format --check .
```

## Roadmap

- [ ] Proper organizational domain lookup using the Public Suffix List
- [ ] BIMI and TLS-RPT checks
- [ ] Docker image
- [ ] Publish to PyPI

## License

MIT
