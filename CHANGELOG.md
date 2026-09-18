# Changelog

All notable changes to MailRadar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses calendar versioning (`YYYY.0M.PATCH`). PyPI normalizes
versions by dropping leading zeros (e.g. `2026.09.8` is published as `2026.9.8`).

## [Unreleased]

### Added
- `--version` option: `mailradar --version` prints `MailRadar <version>` and exits.
  The version is read from `mailradar.__version__`, the single source of truth
  also used by `pyproject.toml`.

## [2026.09.8] - 2026-09-16

### Fixed
- `send`: encryption with a key fetched from a keyserver failed because the key
  was never in the local keyring. The key is now imported into a throwaway
  temporary keyring, so the user's own keyring is left untouched.
- `send`: if a GPG key is found but encryption fails, the report is no longer
  silently sent in plaintext. It is not sent, the report is printed for manual
  delivery and the command exits with code 1.
- Total score could exceed 100 because the raw per-check maximums add up to
  more than 100. The raw score is now normalized to a 0-100 scale.
- DMARC and BIMI tag values containing `=` were truncated.
- An invalid DMARC `pct` value (non-numeric or outside 0-100) no longer crashes
  the analysis: it is reported as an issue and treated as 100 (RFC 7489 §6.3).
- A non-UTF-8 TXT record no longer crashes the analysis.
- `batch`: a domain that fails analysis no longer stops the whole run. It is
  reported and listed in a final "Failed" summary.
- `discover`: the email regex matched look-alike domains (e.g. addresses at
  `example.community` or `example.com.evil.org` when discovering `example.com`).
- `discover`: guessed role addresses (RFC 2142) are now shown separately as
  unverified candidates instead of being mixed with addresses found in public
  sources. They are skipped for domains that publish a null MX (RFC 7505).
- `discover`: GPG lookups for discovered addresses now run in parallel and
  also cover the guessed candidates.

### Security
- DNS records, domain names, keyserver data and report text shown in the
  terminal are escaped, so Rich markup injected via DNS records or other
  external data is no longer interpreted.

## [2026.09.7] - 2026-09-16

### Changed
- Bumped `anyio` from 4.15.0 to 4.15.1.
- CI: bumped GitHub Actions (`actions/checkout`, `actions/setup-python`,
  `docker/setup-qemu-action`, `github/codeql-action`) and aligned all CodeQL
  steps to v4.38.0.

## [2026.09.6] - 2026-09-15

### Changed
- Test coverage raised to 84%, with new tests for the CLI, `discover` and GPG
  modules.

## [2026.09.5] - 2026-09-11

### Changed
- Version bump only. No code changes since 2026.09.4.

## [2026.09.4] - 2026-09-11

### Added
- `release.sh` release automation script.

### Changed
- The Docker image and PyPI publish workflows now run on version tags (`v*`).
  The Docker workflow strips the `v` prefix and leading zeros from the tag to
  match the version published on PyPI.

### Security
- Docker base image moved from Debian Bookworm to Debian Trixie
  (`python:3.12-slim-trixie`) to address OpenSSL CVEs.

## [2026.09.3] - 2026-09-08

### Added
- `send --sign`: sign the outgoing report with the sender's GPG private key
  (clear-signed, using the `--from` address). The passphrase is asked
  interactively.
- `SECURITY.md` security policy with a vulnerability reporting contact and the
  status of known CVEs.
- Built distributions are GPG-signed in the PyPI publish workflow.
- Tests for GPG signing and SMTP sending.

### Changed
- CI: manual `workflow_dispatch` trigger for the publish and Docker workflows,
  SonarCloud analysis for Dependabot PRs, coverage reporting to SonarCloud,
  and CodSpeed benchmarks skipped on PRs that do not touch code.

### Fixed
- The publish workflow imports the signing key from a temporary file.
- Corrected the `codeql-action` commit hash in the Docker workflow.

## [2026.09.2] - 2026-09-06

### Added
- `report` command: generates a ready-to-send email report in Italian or
  English (`--lang it|en`) comparing each check's current state with the
  recommended configuration. Sender details are set with `--name`, `--role`
  and `--org` (placeholders otherwise). `--save` writes the report to a file.
- GPG public key lookup on keyservers (keys.openpgp.org, keyserver.ubuntu.com,
  pgp.mit.edu) for common contact addresses (`security@`, `dpo@`, `admin@`,
  `postmaster@`, `privacy@`). The result is shown as a GPG row in `check` and
  counts toward the score.
- `send` command: analyzes a domain and delivers the report. With a GPG key it
  encrypts the report for the key owner. Without one, it sends in plaintext to
  common security contacts over SMTP (`--smtp-host`, `--smtp-port`,
  `--smtp-user`, `--smtp-pass` or `MAILRADAR_SMTP_PASS`, `--from`). Without
  SMTP settings it prints the report for manual copy-paste.
- `check` verifies that the domain exists in DNS. If it does not, MailRadar
  scans common TLD variants and lets you pick one.
- `discover` command: finds email addresses for a domain from website scraping
  (common contact and privacy pages, including subdomains found via crt.sh
  Certificate Transparency logs), DNS (SOA and TXT records), RDAP and common
  role addresses. It reports which addresses have a GPG public key; skip that
  check with `--no-gpg`.
- Dockerfile and Docker image.
- Release workflows: PyPI publishing, Docker Hub image and GitHub Release.
- CI: CodeQL, SonarCloud, CodSpeed benchmarks, Trivy scanning and Dependabot.
  Dependencies pinned via `uv.lock` and a hash-locked `requirements-ci.txt`.
- Mock-based tests for the checker, GPG and reporter modules.

### Changed
- README examples no longer reference third-party domains.
- GPG keyserver lookups run in parallel and prefer the keys.openpgp.org VKS
  API, falling back to HKP. Before, domains with several candidate addresses
  could hit sequential timeouts.
- CI split into dedicated workflows, with GitHub Actions pinned to commit SHAs.

### Fixed
- Report templates are rendered with an explicit Jinja2 autoescape policy
  (`select_autoescape`: enabled for HTML, disabled for the plain-text `.j2`
  email templates).

### Security
- GPG encryption no longer uses `--trust-model always`.
- The keys.openpgp.org VKS endpoint is selected by parsing the keyserver
  hostname instead of a substring match on the URL.

## [2026.09.1] - 2026-09-04

### Added
- Email security checks for DMARC, SPF, DKIM, BIMI (with VMC detection),
  MTA-STS and TLS-RPT.
- DKIM detection across a list of common selectors, with accurate key size
  detection through the `cryptography` library.
- BIMI SVG logo validation over HTTP.
- MTA-STS policy mode detection.
- Score from 0 to 100 with grade levels (EXCELLENT, GOOD, MODERATE, POOR,
  CRITICAL) and a list of issues with recommendations.
- `check` command (`--verbose` shows raw DNS records) and `batch` command for
  a file with one domain per line.
- Color-coded Rich terminal output.

[Unreleased]: https://github.com/maksimtech/mailradar/compare/v2026.09.8...HEAD
[2026.09.8]: https://github.com/maksimtech/mailradar/compare/v2026.09.7...v2026.09.8
[2026.09.7]: https://github.com/maksimtech/mailradar/compare/v2026.09.6...v2026.09.7
[2026.09.6]: https://github.com/maksimtech/mailradar/compare/v2026.09.5...v2026.09.6
[2026.09.5]: https://github.com/maksimtech/mailradar/compare/v2026.09.4...v2026.09.5
[2026.09.4]: https://github.com/maksimtech/mailradar/compare/v2026.09.3...v2026.09.4
[2026.09.3]: https://github.com/maksimtech/mailradar/compare/v2026.09.2...v2026.09.3
[2026.09.2]: https://github.com/maksimtech/mailradar/compare/v2026.09.1...v2026.09.2
[2026.09.1]: https://github.com/maksimtech/mailradar/releases/tag/v2026.09.1
