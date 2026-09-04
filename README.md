# MailRadar 📡

> **Know your email security posture — before attackers do.**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/mailradar.svg)](https://pypi.org/project/mailradar)
[![Docker](https://img.shields.io/badge/docker-maksimtech%2Fmailradar-blue)](https://hub.docker.com/r/maksimtech/mailradar)
[![GDPR Art. 32](https://img.shields.io/badge/GDPR-Art.%2032-green.svg)](https://gdprhub.eu)

MailRadar is an open-source CLI tool that audits the email security posture of any domain — checking DMARC, SPF, DKIM, BIMI, VMC and GPG key availability — and generates ready-to-send reports for domain owners.

---

## Why MailRadar?

Email authentication is a critical but often overlooked layer of security. A domain without proper DMARC, SPF and DKIM configuration can be spoofed — allowing attackers to impersonate organizations, DPOs, legal contacts or public entities.

Under **GDPR Article 32**, data controllers are required to implement appropriate technical measures to ensure security. A missing or misconfigured DMARC policy is a measurable, documentable gap.

MailRadar makes that gap visible — and actionable.

---

## Features

- ✅ **DMARC** — policy level (none/quarantine/reject), alignment, reporting
- ✅ **SPF** — record presence, permissiveness (-all vs ~all vs +all)
- ✅ **DKIM** — selector detection, key length verification
- ✅ **BIMI** — record presence and SVG logo validation
- ✅ **VMC** — Verified Mark Certificate detection
- ✅ **MTA-STS** — policy presence and mode
- ✅ **TLS-RPT** — TLS reporting configuration
- ✅ **GPG** — public key lookup on keyservers (keys.openpgp.org, keyserver.ubuntu.com)
- ✅ **Security contact** — security@ / postmaster@ / dpo@ detection
- 📊 **Scoring** — 0-100 security score with severity levels
- 📧 **Report generation** — ready-to-send email template with current vs recommended configuration
- 🔐 **GPG-encrypted delivery** — if target has a public key, report is encrypted before sending
- 📄 **PDF export** — formal audit report for GDPR Art. 32 documentation

---

## Real-world example

```
$ mailradar check maksimtech.com

Domain: maksimtech.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ DMARC    p=reject | pct=100 | adkim=s | aspf=s | rua ✓ | ruf ✓
✅ SPF      v=spf1 include:spf.infomaniak.ch -all
✅ DKIM     selector: 20250324 | RSA 2048-bit
⚠️  BIMI     not configured
❌ VMC      not present
✅ MTA-STS  enforce mode
✅ TLS-RPT  configured
✅ GPG      key found on keys.openpgp.org

Score: 85/100 — GOOD
```

```
$ mailradar check protectiontrade.it

Domain: protectiontrade.it
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  DMARC    p=quarantine | adkim=s | aspf=s | rua ✓ | ruf ✓ | BIMI errors
⚠️  SPF      v=spf1 ip4:194.243.136.142 include:spf.protection.outlook.com include:musvc.com -all
❌ DKIM     not found
❌ BIMI     SVG fetch timeout | no VMC
❌ VMC      not present
❌ MTA-STS  not configured
❌ TLS-RPT  not configured
❌ GPG      no public key found

Score: 23/100 — POOR
```

*protectiontrade.it is the external DPO of a major Italian retail cooperative — handling formal GDPR communications for millions of customers.*

---

## Installation

```bash
# Via pip
pip install mailradar

# Via Docker
docker pull maksimtech/mailradar
docker run --rm maksimtech/mailradar check example.com

# From source
git clone https://github.com/maksimtech/mailradar
cd mailradar
pip install -e .
```

---

## Usage

```bash
# Basic check
mailradar check example.com

# Full audit with report generation
mailradar check example.com --report

# Generate PDF for GDPR Art. 32 documentation
mailradar check example.com --report --format pdf

# Check and send report to domain owner
mailradar check example.com --send --from security@yourdomain.com

# Check multiple domains from file
mailradar batch domains.txt

# Historical tracking
mailradar history example.com

# Check GPG key availability
mailradar gpg example.com
```

---

## Scoring

| Score | Level | Description |
|-------|-------|-------------|
| 90-100 | 🟢 EXCELLENT | Full implementation including BIMI+VMC |
| 75-89 | 🟢 GOOD | DMARC p=reject, SPF -all, DKIM configured |
| 50-74 | 🟡 MODERATE | DMARC present but not at reject level |
| 25-49 | 🟠 POOR | Partial or misconfigured authentication |
| 0-24 | 🔴 CRITICAL | No meaningful email authentication |

---

## GDPR Relevance

MailRadar is particularly relevant for:

- **DPOs** auditing the email security posture of data controllers they assist
- **IT managers** documenting technical measures under GDPR Art. 32
- **Security researchers** identifying spoofable domains of public entities
- **Compliance teams** generating evidence for audit trails

A domain with `p=none` DMARC handling sensitive personal data communications is a documentable Art. 32 gap.

---

## Report Template

MailRadar generates localized email reports (IT/EN) with:

- Current configuration (actual DNS records)
- Recommended configuration (copy-paste ready DNS records)
- Provider-specific guidance (Infomaniak, Google Workspace, Microsoft 365, Proton)
- GPG-encrypted delivery if target public key is available on keyservers

---

## Related Projects

- [PatchRadar](https://github.com/maksimtech/patchradar) — CVE monitoring for self-hosted software stacks

---

## Built with

- [dnspython](https://www.dnspython.org/) — DNS toolkit
- [Typer](https://typer.tiangolo.com/) — CLI framework
- [Rich](https://rich.readthedocs.io/) — terminal formatting
- [Jinja2](https://jinja.palletsprojects.com/) — report templates
- [httpx](https://www.python-httpx.org/) — HTTP client for BIMI/VMC validation
- [gnupg](https://gnupg.readthedocs.io/) — GPG key lookup and encryption

---

## Contributing

Contributions welcome. Open an issue or PR on GitHub.

---

## License

MIT — see [LICENSE](LICENSE)

---

*Built by [maksimtech](https://github.com/maksimtech) — also maintaining [PatchRadar](https://github.com/maksimtech/patchradar)*
