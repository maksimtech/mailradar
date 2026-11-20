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

Check the installed version:

```bash
mailradar --version
```

**Docker**

```bash
docker run --rm maksimtech/mailradar check example.com
```

In the image, `report --save` writes to `/home/mailradar/.mailradar`, the
image's volume: mount it (`-v mailradar:/home/mailradar/.mailradar`) to keep
the file after the container exits.

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

`DOMAIN` is a domain name, such as `example.com`. A URL (`https://example.com/`)
or an email address (`security@example.com`) is refused with exit code 64 and a
message that says what to pass instead. Names are read case-insensitively and
without a trailing dot: `Example.COM.` is `example.com` everywhere, the files
`report --save` writes and the addresses `send` writes to included.

Output that comes from outside — DNS records, keyserver answers, an MTA-STS
policy, the pages `discover` reads — is printed exactly as published, with any
control character written out (`\x1b`) rather than sent to the terminal.

### `check`: analyze a domain

```bash
mailradar check example.com
```

Real output:

```
╭──────────────────────────── 📡 MailRadar Report ─────────────────────────────╮
│ Domain: example.com                                                          │
│ Score: 65/100 — 🟡 MODERATE                                                  │
╰──────────────────────────────────────────────────────────────────────────────╯
╭──────────┬─────┬─────────────────────────────────────────────────────┬───────╮
│ Check    │ St… │ Details                                             │ Score │
├──────────┼─────┼─────────────────────────────────────────────────────┼───────┤
│ DMARC    │ ✅  │ p=reject | pct=100 | adkim=s | aspf=s | rua=✗ |     │    45 │
│          │     │ ruf=✗                                               │       │
│ SPF      │ ✅  │ v=spf1 -all                                         │    20 │
│ DKIM     │ ❌  │ selector: default | key revoked                     │     0 │
│ BIMI/VMC │ ❌  │ Not configured                                      │     0 │
│ MTA-STS  │ ❌  │ Not configured                                      │     0 │
│ TLS-RPT  │ ❌  │ Not configured                                      │     0 │
│ GPG      │ ✅  │ uid: security@example.com |                         │     5 │
│          │     │ https://keyserver.ubuntu.com                        │       │
╰──────────┴─────┴─────────────────────────────────────────────────────┴───────╯

⚠️  Issues found:
  • No rua configured — aggregate reports disabled
  • No ruf configured — forensic reports disabled
  • DKIM key revoked (empty p=) on selector default and 16 more — no active key
found
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
you to pick one of those that exist. `report` and `send` do the same before
analysing anything.

**Exit codes**, useful in scripts and monitoring:

| Exit code | Meaning |
|-----------|---------|
| `0` | Grade EXCELLENT or GOOD |
| `1` | Grade MODERATE or POOR, or the domain could not be resolved |
| `2` | Grade CRITICAL |
| `3` | No grade: a DNS lookup got no answer (timeout, SERVFAIL), so the analysis is incomplete |
| `64` | Usage error, for every command: an unknown option, a missing argument, a value that is not accepted (`--lang de`, a URL instead of a domain). Click's own code for this is 2, which is also CRITICAL above |

### `batch`: analyze several domains

```bash
mailradar batch domains.txt
```

The file contains one domain per line. Blank lines and lines starting with `#`
are ignored. MailRadar prints the full report for each domain, then a summary
table sorted from the lowest to the highest score. A line that is not a domain
(a URL, an address), a domain that does not exist in DNS, or one whose analysis
fails is reported and skipped; the others still run.

The exit code is the highest one `check` would give any domain in the file,
with a domain that was skipped counting as `1`, as it does in `check`: `0` only
when every domain was analysed and graded EXCELLENT or GOOD, `2` when the worst
is CRITICAL, `3` when an analysis could not be completed.

### `report`: generate a report for the domain owner

```bash
mailradar report example.com --lang en \
  --name "Jane Doe" --role "Security Officer" --org "Example Ltd" \
  --save
```

The report is plain text, ready to paste into an email. For each check it
shows the current record and the recommended configuration (for example a
complete `v=DMARC1; p=reject; ...` record), then your signature. The note on
GDPR Article 32 is included only when the letter lists a problem with DMARC,
SPF or DKIM: BIMI, MTA-STS and TLS-RPT are improvements, the informational SPF
notes (see [SPF](#spf-up-to-20-points)) are listed without turning the section
into an action, and a missing GPG key is a suggestion, not an Article 32 gap.

| Option | Description |
|--------|-------------|
| `--lang`, `-l` | `it` (default) or `en`, in any case (`IT` is `it`). Any other value is refused with exit code 64 |
| `--name`, `--role`, `--org` | Sender details. If omitted, placeholders are left in the text |
| `--save`, `-s` | Also write the report to `mailradar_<domain>_<YYYYMMDD>_<lang>.txt` in the current directory. `<domain>` is the analysed name reduced to `a-z`, `0-9`, `.` and `-`; a file that cannot be written is reported, with exit code 1 |

### `send`: deliver the report

```bash
export MAILRADAR_SMTP_PASS='...'
mailradar send example.com --lang en \
  --name "Jane Doe" --role "Security Officer" --org "Example Ltd" \
  --smtp-host mail.example.org --smtp-user jane@example.org \
  --from jane@example.org
```

`send` runs the analysis, generates the report and delivers it as follows:

1. **The domain has a published GPG key** (see [GPG](#gpg-up-to-5-points)
   below): the report is encrypted to that key and sent to the key's address.
   Without SMTP settings, the encrypted text is printed so you can send it
   yourself. If encryption fails, nothing is sent, the report is printed in
   clear so you can deliver it manually, and the command exits with code 1.
   MailRadar never falls back to sending unencrypted.

   Only a key keys.openpgp.org publishes for the address (its owner confirmed
   it) is used on its own. A key from keyserver.ubuntu.com, where anyone can
   upload a key under any address, is used only once you have confirmed its
   fingerprint with the domain and pass it with `--gpg-fingerprint`; it must
   match the key found, and gpg encrypts to that fingerprint and no other.
   Without it, nothing is sent and nothing is encrypted: `send` prints the
   fingerprint, the reason and the report for a manual send, and exits with
   code 1. If keys.openpgp.org did not answer while keyserver.ubuntu.com did,
   `send` says so: a verified key may exist.
2. **No GPG key, SMTP configured**: the report is sent in plaintext to the
   first of `security@`, `dpo@`, `privacy@`, `admin@`, `postmaster@` that the
   SMTP server accepts — only when every keyserver answered. If one did not
   (HTTP 429, a timeout), a key may exist: nothing is sent, and the command
   exits with code 1; try again later. Only a refused recipient moves on to
   the next address. Any other failure — a wrong password, a certificate that
   does not verify, a server that cannot be reached — ends the attempt at once,
   so a wrong password costs one login and not five.
3. **No SMTP settings**: the report is printed for copy-paste, with suggested
   recipients.

A message the server accepted after `DATA` counts as sent, whatever it answers
to `QUIT`. Whenever SMTP delivery was configured and did not happen, `send`
says why and exits with code 1. The letter's own "Subject:" line is left out
of the body of the message it sends: it is already the Subject header.

| Option | Description |
|--------|-------------|
| `--smtp-host` | SMTP server |
| `--smtp-port` | SMTP port (default `465`, implicit TLS: SMTPS). On `587`, the submission port, the connection uses STARTTLS |
| `--smtp-starttls` | Connect in plain text and upgrade with STARTTLS, on any port. The certificate and the host name are verified either way |
| `--smtp-user` | SMTP username |
| `--smtp-pass` | SMTP password. Prefer the `MAILRADAR_SMTP_PASS` environment variable, so the password does not end up in your shell history |
| `--from` | Sender address |
| `--sign` | Clear-sign the report with your own GPG private key for the `--from` address. Without `--from` it is a usage error (exit code 64). The passphrase is asked before sending starts; if signing fails (a wrong passphrase, no secret key), nothing is sent and the command exits with code 1 |
| `--gpg-fingerprint` | The fingerprint of the recipient's key, confirmed with the domain. Required to encrypt to a key found on a keyserver that does not verify addresses, and it must match that key (spaces and a `0x` prefix are ignored). Given when no key is found, nothing is sent rather than plaintext |
| `--lang`, `--name`, `--role`, `--org` | As in `report`. With SMTP configured they are required: a report would otherwise reach the recipient signed "[NOME]", and `send` refuses, before asking anything of the network |

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
(🔐), which tells you where an encrypted report can be sent. An address no
keyserver answered for (HTTP 429, a timeout) is listed as not verified, not as
an address without a key. Skip this check with `--no-gpg`.

Addresses are read whole, as RFC 5322 writes them (`o'brien@`, `first.last+tag@`,
and the letters of other scripts, `josé.dpo@`); a `mailto:` link is decoded first
(`mailto:%20dpo@` is `dpo@`), and a local part that is not a valid one is left
out rather than reported in part. An SOA contact written with an escaped dot
(`john\.doe.example.com.`) is `john.doe@`. Redirects are followed only to
`https://`, and only to a host of the same registrable domain or to one whose
addresses are all public: a redirect to `http://127.0.0.1` is not followed.

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

When a DNS lookup gets no answer — a timeout, a SERVFAIL, a company network
that lets no DNS out — the check is "not verified", and the analysis gets no
score: `Score: N/A`, the checks that were not verified named beside it, exit
code 3. Counting them as 0 points read as a domain measured at the bottom of
the scale. A keyserver that does not answer is the exception: it withholds at
most the 5 GPG points, and the GPG check says it was not verified.

DMARC, SPF and DKIM account for 85 of the 108 points. They decide whether the
domain can be spoofed. The other checks are hardening measures.

In the table, ✅ means the check is correctly configured, ⚠️ that it is
present but weaker than recommended, and ❌ that it is missing. Every point
lost appears under **Issues found** with the action to take. Each check's
points are coloured by the share of that check's maximum they are (20 of 20
for SPF is green), and a check that was not verified shows `—`, not `0`.

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

Subdomains are resolved the way RFC 7489 §6.6.3 prescribes: if
`_dmarc.<domain>` has no record, the record of the organizational domain
applies, and no name in between is asked. The organizational domain comes from
the [Public Suffix List](https://publicsuffix.org/) shipped with the package.
For `asufc.sanita.fvg.it` that means `_dmarc.asufc.sanita.fvg.it`, then
`_dmarc.sanita.fvg.it`: `fvg.it` is itself on the list, like `it`, `co.uk` or
`co.at`. For `sub.a.example.com` it means `_dmarc.sub.a.example.com`, then
`_dmarc.example.com`: a record on `a.example.com` is not consulted. The public
suffix itself is never queried — a record on it is not the domain's policy.
Two DMARC records on the same name are reported as such: receivers then apply
no DMARC policy at all. An inherited record is marked `via <organizational
domain>` in the table and listed under Issues found, since the subdomain has no
policy of its own; where that record publishes `sp=`, that is the policy scored
for the subdomain.

A `p=` or `sp=` that is not `none`, `quarantine` or `reject` (or a record with
no `p=`) is never shown as the policy. As §6.6.3 says, such a record acts as
`p=none` when its `rua=` names a valid URI, and otherwise no DMARC applies; the
issue names the value. `rua=` and `ruf=` count only for entries that are URIs:
`rua=dmarc@example.com` is an address without `mailto:` and turns no reports on.

### SPF (up to 20 points)

SPF (a TXT record on the domain) lists the servers allowed to send mail for
the domain. What matters most is how it ends:

| Ending | Points | Meaning |
|--------|--------|---------|
| `-all` | 20 | Hard fail: other servers are not allowed. Recommended |
| `~all` | 10 | Soft fail: mail from other servers is only marked as suspicious |
| `?all` | 5 | Neutral: no enforcement |
| `+all` | 0 | Any server may send as the domain. Critical |

The record is read term by term, as RFC 7208 defines it: `all` with no
qualifier is `+all`, names are case-insensitive (`-ALL` is `-all`), and a
record without `all` follows its `redirect=`; with neither, the result is
neutral. These are a permerror, for which receivers apply no SPF and the check
scores 0: two SPF records on the domain; more than 10 DNS lookups once
`include:` and `redirect=` are followed; an `include:` or `redirect=` whose
target has no SPF record, or two; and a syntax error anywhere in the record or
in one it pulls in, named in the issue: an unknown mechanism (`foo:bar`), a typo
of `all` (`-al`, `-all;`), `redirect=` twice, or an `ip4:`/`ip6:` value outside
the RFC 7208 grammar (a netmask, `/027`, a prefix length past 32 or 128, a zone
id). A modifier with an unknown name (`foo=bar`) is allowed, as the RFC says. A
passing range of length 0 (`ip4:0.0.0.0/0`, `ip6:::/0`) lets any server pass
and scores as `+all`.

Three more findings change no points and are reported as notes, not issues: a
record at exactly 10 lookups, which the next `include:` breaks (or "at least N"
when an `include:` or `redirect=` uses a macro, which is counted but not
followed); an `ip4:` or `ip6:` range written from an address inside it
(`ip4:192.0.2.98/27` authorises all of `192.0.2.96/27`, 32 addresses, and
`-ip4:` denies all of it); and a range the domain lists although a record it
pulls in already authorises it. That one is said only when the evaluation
reaches the other range first for every address: not when it comes after an
`all`, or after a term that may fail or softfail those addresses first, or
through an `include:` that does not pass. The note names the domain's own
`include:` or `redirect=`, and the records in between.
Kept in `SPFResult.notes`, they are printed under **Notes**, apart from the
issues, and the letter lists them as notes without asking for action.

### DKIM (up to 15 points)

DKIM signs outgoing mail with a key published at
`<selector>._domainkey.<domain>`. The selector is not public, so MailRadar
tries 33 common ones — Google (`google`), Microsoft 365 (`selector1`,
`selector2`), Proton (`protonmail`, `protonmail2`, `protonmail3`), Fastmail
(`fm1`-`fm3`), Amazon SES, Zendesk, Mailchimp, SendGrid, Mimecast, Postmark,
`default`, `mail`, `dkim` and others — and asks for every one of them: a
receiver verifies a signature made with any published key, so the weakest key
found is the one measured, and the table names them all (`selector1: 1024-bit
RSA | selector2: 2048-bit RSA`). An Ed25519 key (`k=ed25519`, RFC 8463) scores
like a 2048-bit RSA key. An empty `p=` is a revoked key (RFC 6376 §3.6.1): it
does not count, and the revocation is reported if no active key is found.

Only `v=DKIM1` records, or records without `v=` that carry DKIM's own tags, are
read as keys: a DMARC record published under a selector is not one. The key
size is read from the key itself, never estimated from the length of `p=`. A key
that does not decode as the type it declares (SubjectPublicKeyInfo or PKCS#1 for
RSA, 32 bytes for Ed25519), a `k=` no RFC defines, or a record with no `p=` at all
is reported as malformed — signatures cannot be verified with it — and scores 0.
A key with `t=y` is in testing mode, and RFC 6376 §3.6.1 tells verifiers to treat
its mail as unsigned: it is reported and scores 0 too. Either kind decides the
score only when no other key works; a domain with one malformed or testing
selector beside a working key is scored by the working key. A domain so long
that every `<selector>._domainkey.<domain>` passes 255 octets can publish no
key, and is told so.

| Key size | Points |
|----------|--------|
| 2048 bits or more | 15 |
| 1024 bits | 10 (upgrade recommended) |
| Smaller | 3 (upgrade immediately) |

"Not found under 33 common selectors" is not "DKIM missing": Amazon,
Proofpoint customers and many others sign under selectors of their own. The
`s=` tag of a received message's `DKIM-Signature` header says which.

### BIMI / VMC (up to 10 points)

BIMI (`default._bimi.<domain>`) lets supporting mail clients show the
organization's logo. MailRadar checks that the SVG logo is reachable (2
points) and whether a Verified Mark Certificate is referenced (8 points, or 3
without a VMC). The logo is downloaded only from an `https://` URL that does
not name a private or loopback address, since the URL comes from the analysed
domain's DNS; that includes the IPv4 forms `getaddrinfo` accepts on Linux
(`127.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`), and a host made of numbers
alone that is no address at all. A logo or VMC URL that cannot be parsed is
reported as malformed, and `a=` counts as a VMC only if it is an `https://` URL.
`v=BIMI1; l=; a=;` declines BIMI and scores 0; the letter reports it as the
domain's choice, without recommending a record. Mail clients show a BIMI logo
only for a domain whose DMARC policy is `quarantine` or `reject`: beside
`p=none`, or no DMARC, BIMI scores 0 and the issue says why. BIMI is a trust
and branding feature, not a protection against spoofing by itself.

### MTA-STS (up to 5 points)

MTA-STS (`_mta-sts.<domain>` plus the policy file at
`https://mta-sts.<domain>/.well-known/mta-sts.txt`) forces other servers to
deliver mail to the domain over verified TLS. `enforce` mode scores 5 points,
`testing` mode 2.

Both parts are read as senders read them (RFC 8461 §3.1 and §3.2). Only a TXT
record that begins with `v=STSv1` counts; with two of them, or one without a
valid `id=`, senders look for no policy, and none is fetched. The policy file
needs `version: STSv1`, a `mode`, `max_age`, and an `mx` line in `enforce` or
`testing` mode: a file that lacks any of them is no policy, scores 0, and the
issue names what is missing.

### TLS-RPT (up to 3 points)

TLS-RPT (`_smtp._tls.<domain>`) asks other servers to report TLS delivery
failures. The table shows where the reports are sent. As RFC 8460 §3 has it,
the record needs a `rua=` with at least one `mailto:` or `https:` URI, and with
two `v=TLSRPTv1` records senders assume there is none: either scores 0.

### GPG (up to 5 points)

MailRadar searches public keyservers (keys.openpgp.org, keyserver.ubuntu.com)
for a key published for exactly `security@`, `dpo@`, `admin@`, `postmaster@`
or `privacy@` at the domain. A published key means security issues can be
reported to the organization confidentially. The first key found is the one
`send` uses for encryption.

The 5 points go only to a key keys.openpgp.org lists, because that server
publishes an address only after its owner answered a verification mail.
keyserver.ubuntu.com lists whatever anyone uploads under any name: a key found
there is shown with its fingerprint and "address not verified", scores
nothing, and should be confirmed with the domain before use. A keyserver that
does not answer (HTTP 429 — keys.openpgp.org allows one by-email lookup a
minute, with a burst of 50 — or a timeout) is not asked again during the
analysis and leaves the check "not verified", which is not "no key". When
keys.openpgp.org does not answer and keyserver.ubuntu.com lists a key, the
issues say that a verified key may exist all the same. A key whose expiration
date has passed is not used, whether or not the keyserver marks it expired.

`send` encrypts with gpg in a throwaway keyring that only looks at the key it
was given (`--auto-key-locate clear,local`, `--no-auto-key-retrieve`): gpg does
not go looking for another key on the network, and whatever daemons it started
for that keyring are stopped before the keyring is deleted. No published key
is a suggestion, printed under the provisions applied; it is not cited as a
GDPR Article 32 gap.

### MX (no points)

MailRadar reads the domain's MX records to see whether a domain that sends
mail can also receive it. A domain sends mail when its SPF record names a
sender or it publishes a DKIM key; one that publishes only `v=spf1 -all` and no
key sends none, and nothing is said about its MX.

- **No MX** is a note: replies and bounces go to the domain's own A/AAAA
  address, if it has one (RFC 5321 §5.1, implicit MX), and some spam filters
  score mail whose From domain has no MX.
- **A null MX** (`0 .`, RFC 7505) is an issue: the domain declares it accepts
  no mail, RFC 7505 §4.2 says a domain used to send mail should not publish
  one, and §4.1 gives receivers a code (550 5.7.27) to reject its mail with.

An MX lookup that gets no answer says nothing either way; it does not make the
analysis "not verified", since MX is not scored.

---

## Known limitations

- DKIM detection depends on the list of common selectors (see above).
- A DNS lookup that fails (timeout, SERVFAIL) leaves that check "not
  verified": it scores 0 but is not reported as missing, and `report` and
  `send` refuse to produce a report from an incomplete analysis. So does an
  MTA-STS policy fetch or a BIMI logo fetch that gets no answer (a timeout, a
  reset, a refused connection to a host that DNS gives an address): that says
  something about the network the scan runs from. An HTTP status such as 404,
  or a policy host that DNS does not know, is the domain's answer and is scored.
- A domain that is not a valid DNS name (a label past 63 octets, a name past
  255, invalid IDNA) is reported as such, not as a DNS failure.
- SPF macros (`%{d}` and the like) are not expanded, so an `include:` or
  `redirect=` that uses one is counted but not followed: the lookup count is
  then "at least N", and a verdict handed to such a `redirect=` is reported as
  not checked. The limit of two void lookups is not checked either, nor are
  the domain names in SPF terms against the grammar, only that they are there.
- The BIMI logo host name is not checked for resolving to a private address,
  and the VMC is not downloaded or validated: "VMC" means that `a=` names one.
- A key keyserver.ubuntu.com publishes for the address is reported as "not
  verified": that server does not check who uploads a key, and `send` uses it
  only with its fingerprint confirmed through `--gpg-fingerprint`.
- `send` looks for a key under the five contact addresses in order and takes
  the first one found: a key keyserver.ubuntu.com lists for `security@` comes
  before a verified one keys.openpgp.org lists for `dpo@`.
- `discover` checks where a redirect leads, not the addresses of the
  subdomains it finds on crt.sh before requesting them.

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

## Security

Report a vulnerability as described in [SECURITY.md](SECURITY.md), which also gives
the response times, how customers are told and how to roll back.

Every GitHub release carries CycloneDX SBOMs of the Docker image and of the Python
environment, and dated Trivy reports of the image and of the repository at the tag.
They are an automated scan for known vulnerabilities, not a penetration test.

For customers subject to NIS2, [docs/nis2-compliance.md](docs/nis2-compliance.md)
(in Italian) answers the seven questions a supplier of software gets asked: what the
software is made of, which hosts it contacts and with what data, how it is checked
before release, and what it does not have.

---

## Contributing

Contributions are welcome. Open an issue or a pull request on
[GitHub](https://github.com/maksimtech/mailradar). See [SECURITY.md](SECURITY.md)
to report a vulnerability and [CHANGELOG.md](CHANGELOG.md) for the release
history.

---

## How this is built

Developed with [Claude Code](https://claude.com/claude-code), reviewed and released by
[maksimtech](https://github.com/maksimtech). The suite is the contract: the release
script runs it with the new version already written and refuses to commit if it fails,
so nothing ships that it has not passed.

---

## License

MIT — see [LICENSE](LICENSE).

One file in the package is not MIT and not ours: `mailradar/public_suffix_list.dat`
is the [Public Suffix List](https://publicsuffix.org) maintained by Mozilla, shipped
unmodified and distributed under the Mozilla Public License 2.0
([MPL-2.0](https://mozilla.org/MPL/2.0/)), as its header states.

---

*Built by [maksimtech](https://github.com/maksimtech).*
