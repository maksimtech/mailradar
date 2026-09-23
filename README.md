# MailRadar 📡

> **Know your email security posture — before attackers do.**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/mailradar.svg)](https://pypi.org/project/mailradar)
[![Docker](https://img.shields.io/badge/docker-maksimtech%2Fmailradar-blue)](https://hub.docker.com/r/maksimtech/mailradar)

MailRadar is an open-source command-line tool that audits the email security
posture of a domain. It reads the domain's public DNS records and related
endpoints, checks DMARC, SPF, DKIM, BIMI/VMC, MTA-STS and TLS-RPT, looks for a
published GPG key for the domain's security contacts, and computes a score
from 0 to 100.

It can also turn the result into a ready-to-send report (Italian or English)
for the domain owner, and deliver it by email, GPG-encrypted when the
recipient has a public key.

MailRadar only performs passive, public lookups: DNS queries and HTTPS
requests to public endpoints. It never sends email unless you run `send` with
SMTP credentials.

---

## Why it matters

A domain without a strict DMARC policy, a hard-fail SPF record and DKIM
signing can be spoofed: anyone can send mail that appears to come from it.
For organizations that handle personal data, this is a concrete, documentable
gap under **GDPR Article 32** (security of processing).

MailRadar makes that gap measurable, for sysadmins who need to fix it and for
DPOs who need to document it.

---

## Installation

MailRadar requires **Python 3.11 or later**.

```bash
pip install mailradar
```

Check the installed version (`--version` is not yet in a published release;
see [CHANGELOG.md](CHANGELOG.md)):

```bash
mailradar --version
```

**Docker**

```bash
docker run --rm maksimtech/mailradar check example.com
```

**From source**

```bash
git clone https://github.com/maksimtech/mailradar
cd mailradar
pip install -e .
```

The `send` command uses the `gpg` binary (GnuPG) to encrypt and sign reports.
Install it through your system package manager if you plan to use those
features. The Docker image already includes it.

---

## Commands

| Command | What it does |
|---------|--------------|
| `check DOMAIN` | Analyze a domain and print the score, per-check results and issues |
| `batch FILE` | Analyze every domain listed in a file and print a summary |
| `report DOMAIN` | Analyze a domain and generate a ready-to-send email report |
| `send DOMAIN` | Analyze a domain and deliver the report to its security contact |
| `discover DOMAIN` | Find contact email addresses for a domain from public sources |

Run `mailradar COMMAND --help` for the full list of options.

### `check`: analyze a domain

```bash
mailradar check example.com
```

Real output:

```
╭──────────────────────────── 📡 MailRadar Report ─────────────────────────────╮
│ Domain: example.com                                                          │
│ Score: 68/100 — 🟡 MODERATE                                                  │
╰──────────────────────────────────────────────────────────────────────────────╯
╭──────────┬─────┬─────────────────────────────────────────────────────┬───────╮
│ Check    │ St… │ Details                                             │ Score │
├──────────┼─────┼─────────────────────────────────────────────────────┼───────┤
│ DMARC    │ ✅  │ p=reject | pct=100 | adkim=s | aspf=s | rua=✗ |     │    45 │
│          │     │ ruf=✗                                               │       │
│ SPF      │ ✅  │ v=spf1 -all                                         │    20 │
│ DKIM     │ ✅  │ selector: default | 512-bit RSA                     │     3 │
│ BIMI/VMC │ ❌  │ Not configured                                      │     0 │
│ MTA-STS  │ ❌  │ Not configured                                      │     0 │
│ TLS-RPT  │ ❌  │ Not configured                                      │     0 │
│ GPG      │ ✅  │ uid: security@example.com |                         │     5 │
│          │     │ https://keyserver.ubuntu.com                        │       │
╰──────────┴─────┴─────────────────────────────────────────────────────┴───────╯

⚠️  Issues found:
  • No rua configured — aggregate reports disabled
  • No ruf configured — forensic reports disabled
  • DKIM key is weak — upgrade to 2048-bit immediately
  • No BIMI record configured
  • No MTA-STS configured
  • No TLS-RPT configured
```

Show the raw DMARC, SPF, DKIM and BIMI records as well:

```bash
mailradar check example.com --verbose
```

If the domain does not resolve in DNS, `check` tries common TLD variants of
the name (`.com`, `.it`, `.eu`, `.org`, `.de`, `.co.uk` and others) and asks
you to pick one of those that exist.

**Exit codes**, useful in scripts and monitoring:

| Exit code | Meaning |
|-----------|---------|
| `0` | Grade EXCELLENT or GOOD |
| `1` | Grade MODERATE or POOR, or the domain could not be resolved |
| `2` | Grade CRITICAL |

### `batch`: analyze several domains

```bash
mailradar batch domains.txt
```

The file contains one domain per line. Blank lines and lines starting with `#`
are ignored. MailRadar prints the full report for each domain, then a summary
table sorted from the lowest to the highest score. A domain that fails
analysis is reported and skipped; the others still run.

### `report`: generate a report for the domain owner

```bash
mailradar report example.com --lang en \
  --name "Jane Doe" --role "Security Officer" --org "Example Ltd" \
  --save
```

The report is plain text, ready to paste into an email. For each check it
shows the current record and the recommended configuration (for example a
complete `v=DMARC1; p=reject; ...` record), followed by a short note on GDPR
Article 32 and your signature.

| Option | Description |
|--------|-------------|
| `--lang`, `-l` | `it` (default) or `en` |
| `--name`, `--role`, `--org` | Sender details. If omitted, placeholders are left in the text |
| `--save`, `-s` | Also write the report to `mailradar_<domain>_<YYYYMMDD>_<lang>.txt` in the current directory |

### `send`: deliver the report

```bash
export MAILRADAR_SMTP_PASS='...'
mailradar send example.com --lang en \
  --name "Jane Doe" --role "Security Officer" --org "Example Ltd" \
  --smtp-host mail.example.org --smtp-user jane@example.org \
  --from jane@example.org
```

`send` runs the analysis, generates the report and delivers it as follows:

1. **The domain has a published GPG key** (see [GPG](#gpg) below): the report
   is encrypted to that key and sent to the key's address. Without SMTP
   settings, the encrypted text is printed so you can send it yourself.
   If encryption fails, nothing is sent, the report is printed in clear so
   you can deliver it manually, and the command exits with code 1. MailRadar
   never falls back to sending unencrypted.
2. **No GPG key, SMTP configured**: the report is sent in plaintext to the
   first of `security@`, `dpo@`, `privacy@`, `admin@`, `postmaster@` that the
   SMTP server accepts.
3. **No SMTP settings**: the report is printed for copy-paste, with suggested
   recipients.

| Option | Description |
|--------|-------------|
| `--smtp-host` | SMTP server |
| `--smtp-port` | SMTP port (default `465`). The connection uses implicit TLS (SMTPS) |
| `--smtp-user` | SMTP username |
| `--smtp-pass` | SMTP password. Prefer the `MAILRADAR_SMTP_PASS` environment variable, so the password does not end up in your shell history |
| `--from` | Sender address |
| `--sign` | Clear-sign the report with your own GPG private key for the `--from` address (requires `--from`). The passphrase is asked interactively |
| `--lang`, `--name`, `--role`, `--org` | As in `report` |

SMTP delivery happens only when `--smtp-host`, `--smtp-user`, the password
and `--from` are all set.

### `discover`: find contact addresses

```bash
mailradar discover example.com
```

`discover` looks for email addresses at the domain in public sources:

- **Website**: the home page and common contact and privacy pages of the
  domain (`/contact`, `/contatti`, `/privacy`, `/privacy-policy`, `/about`,
  `/chi-siamo`), plus the home, `/privacy` and `/contatti` pages of `www.`
  and of up to 10 subdomains found in Certificate Transparency logs (crt.sh).
- **DNS**: the SOA record's responsible-person address and TXT records.
- **RDAP**: the registration data of the domain.

Addresses actually found are listed by source. Common role addresses
(RFC 2142, such as `security@`, `dpo@`, `abuse@`) are listed separately as
**unverified candidates**, and only when the domain accepts email (it has MX
records and no null MX).

For every address, MailRadar checks whether a GPG public key is published
(🔐), which tells you where an encrypted report can be sent. Skip this check
with `--no-gpg`.

---

## Reading the results

### Score and grade

Each check awards points. The raw total (maximum 108) is scaled to 0–100.

| Score | Grade | Typical meaning |
|-------|-------|-----------------|
| 90–100 | 🟢 EXCELLENT | Strict DMARC, SPF and DKIM, plus most of BIMI/VMC, MTA-STS, TLS-RPT and GPG |
| 75–89 | 🟢 GOOD | Core authentication (DMARC, SPF, DKIM) is strong |
| 50–74 | 🟡 MODERATE | Authentication is present but has gaps |
| 25–49 | 🟠 POOR | Authentication is partial or misconfigured |
| 0–24 | 🔴 CRITICAL | No meaningful email authentication |

DMARC, SPF and DKIM account for 85 of the 108 points. They decide whether the
domain can be spoofed. The other checks are hardening measures.

In the table, ✅ means the check is correctly configured, ⚠️ that it is
present but weaker than recommended, and ❌ that it is missing. Every point
lost appears under **Issues found** with the action to take.

### DMARC (up to 50 points)

DMARC (`_dmarc.<domain>`) tells receiving servers what to do with mail that
fails SPF and DKIM checks. It is the single most important record.

| Element | Points | Recommended |
|---------|--------|-------------|
| Policy `p=` | reject 30, quarantine 15, none 0 | `p=reject`: spoofed mail is refused. `p=none` only monitors and offers no protection |
| `pct=` | 5 if 100 | Apply the policy to 100% of messages |
| `adkim=` / `aspf=` | 5 each if strict (`s`) | Strict alignment between the visible From domain and the DKIM/SPF domain |
| `rua=` | 3 | Receive aggregate reports, to see who sends mail as your domain |
| `ruf=` | 2 | Receive failure (forensic) reports |

A missing DMARC record means the domain is spoofable. The ✅ status is shown
only for `p=reject`.

Multi-level domains are resolved the way RFC 7489 §6.6.3 prescribes: if
`_dmarc.<domain>` has no record, one label is removed at a time up to the
organizational domain. For `asufc.sanita.fvg.it` that means
`_dmarc.asufc.sanita.fvg.it`, then `_dmarc.sanita.fvg.it`, then
`_dmarc.fvg.it`. The public suffix itself is never queried — a record on `it`
or `co.uk` is not the domain's policy. An inherited record is marked
`via <parent domain>` in the table and listed under Issues found, since the
subdomain has no policy of its own; where the parent publishes `sp=`, that is
the policy scored for the subdomain.

### SPF (up to 20 points)

SPF (a TXT record on the domain) lists the servers allowed to send mail for
the domain. What matters most is how it ends:

| Ending | Points | Meaning |
|--------|--------|---------|
| `-all` | 20 | Hard fail: other servers are not allowed. Recommended |
| `~all` | 10 | Soft fail: mail from other servers is only marked as suspicious |
| `?all` | 5 | Neutral: no enforcement |
| `+all` | 0 | Any server may send as the domain. Critical |

MailRadar also flags `+a` and `+mx` mechanisms as too permissive.

### DKIM (up to 15 points)

DKIM signs outgoing mail with a key published at
`<selector>._domainkey.<domain>`. The selector is not public, so MailRadar
tries a list of common ones (`default`, `google`, `selector1`, `selector2`,
`k1`, `mail` and others) and measures the RSA key size of the first one found.

| Key size | Points |
|----------|--------|
| 2048 bits or more | 15 |
| 1024 bits | 10 (upgrade recommended) |
| Smaller | 3 (upgrade immediately) |

"Not found" does not always mean DKIM is missing: the domain may use a
selector outside the list.

### BIMI / VMC (up to 10 points)

BIMI (`default._bimi.<domain>`) lets supporting mail clients show the
organization's logo. MailRadar checks that the SVG logo is reachable (2
points) and whether a Verified Mark Certificate is referenced (8 points, or 3
without a VMC). BIMI is a trust and branding feature, not a protection
against spoofing by itself.

### MTA-STS (up to 5 points)

MTA-STS (`_mta-sts.<domain>` plus the policy file at
`https://mta-sts.<domain>/.well-known/mta-sts.txt`) forces other servers to
deliver mail to the domain over verified TLS. `enforce` mode scores 5 points,
`testing` mode 2.

### TLS-RPT (up to 3 points)

TLS-RPT (`_smtp._tls.<domain>`) asks other servers to report TLS delivery
failures. The table shows where the reports are sent.

### GPG (up to 5 points)

MailRadar searches public keyservers (keys.openpgp.org, keyserver.ubuntu.com,
pgp.mit.edu) for a key published for `security@`, `dpo@`, `admin@`,
`postmaster@` or `privacy@` at the domain. A published key means security
issues can be reported to the organization confidentially. The first key
found is the one `send` uses for encryption.

---

## Known limitations

- DKIM detection depends on the list of common selectors (see above).
- An empty DKIM key (`p=`, which revokes the key) is reported as a weak
  512-bit key, as in the `example.com` output above.
- The GPG check confirms that a key is published for the address, not that
  the address's owner controls it: keyserver.ubuntu.com and pgp.mit.edu do
  not verify email addresses. Check the key before relying on it for
  sensitive reports.
- `send` supports SMTP over implicit TLS only (SMTPS, usually port 465).
- With `send --sign`, if signing fails (for example a wrong passphrase) the
  report is sent unsigned.

---

## Related projects

- [PatchRadar](https://github.com/maksimtech/patchradar) — CVE monitoring for self-hosted software stacks

---

## Built with

- [dnspython](https://www.dnspython.org/) — DNS queries
- [cryptography](https://cryptography.io/) — DKIM key size detection
- [httpx](https://www.python-httpx.org/) — BIMI, MTA-STS, keyserver and discovery requests
- [Jinja2](https://jinja.palletsprojects.com/) — report templates
- [Typer](https://typer.tiangolo.com/) — command-line interface
- [Rich](https://rich.readthedocs.io/) — terminal output

---

## Contributing

Contributions are welcome. Open an issue or a pull request on
[GitHub](https://github.com/maksimtech/mailradar). See [SECURITY.md](SECURITY.md)
to report a vulnerability and [CHANGELOG.md](CHANGELOG.md) for the release
history.

---

## License

MIT — see [LICENSE](LICENSE).

---

*Built by [maksimtech](https://github.com/maksimtech).*
