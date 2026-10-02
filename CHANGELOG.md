# Changelog

All notable changes to MailRadar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses **CalVer, Apple style**: `YYYY.count[.fix]`, not SemVer.
`YYYY` is the generation, shared by the five Radar; the count belongs to each of
them and moves when its code moves; the third segment is for something urgent on
what has already shipped. The line above described `YYYY.0M.PATCH` until
2026-09-29, which no version in this file has ever matched — 40 is not a month,
and `tests/test_version_contract.py` has been enforcing the real form all along.

## [Unreleased]


### Added

- **The gate reads FIRST's forecast on the CVEs it already holds.** EPSS is indexed
  by CVE, and `SECURITY-EXCEPTIONS.toml` is the one surface in this repository that
  holds CVE ids: Docker Scout names its alerts by CVE, so every accepted finding
  already has an id, a written reason and a review date. The forecast is what those
  records lacked — "no fix in any suite" accepted until December is comfortable at
  an EPSS of 0.1% and is something else at 40%.

  The forecast changes no verdict. The gate fails on a blocking alert with no entry
  and on an entry past its date, and on nothing else: `exit_code` takes the
  forecasts and ignores them, so the signature says they were available and did not
  decide anything. Only ids that *are* CVE ids are looked up —
  `SNYK-DEBIAN13-GCC14-20386241` is CVE-2026-95619 and says so in its description,
  and reading prose is guessing. A CVE FIRST does not score prints "not scored by
  FIRST" rather than 0.0%, which is a real reading at the floor of the scale; FIRST
  unreachable prints nothing and the report is the one this script produced before.

  The accepted findings are listed on a **passing** run, worst first, because that
  is where somebody decides whether to renew a review date and nothing else prompts
  it.

  Ported from patchradar with its nineteen tests; `tools/security_exceptions.py` is
  shared by copy across the five, and all four copies were byte-identical before
  this.

### Fixed

- **A test was pinning Rich's output stream for every test that ran after it.**
  `test_the_console_is_flushed_even_when_the_body_raises` saved `cli.console.file`
  and assigned it back, which looks like a restore and is not: Rich's `file` is a
  property that falls back to `sys.stdout` when nothing was set, so writing the
  current value into it fixes that stream for good. Any later test rendering
  through this console then wrote to the terminal instead of to the CliRunner's
  buffer. Measured on apkradar, where the sibling of this test left
  `tests/test_hash_is_verifiable.py` asserting against an empty `result.output`;
  the suite passed only because of the order the files happen to be collected in.
  The test now builds a console of its own and puts it in place of the module's,
  through monkeypatch.

### Changed

- **ruff now lints `tools/` as well, because it never did.** Every one of the five
  Radar lints its package and its tests and stops there, which left
  `tools/security_exceptions.py` outside the check — the script that refuses a build
  over an unexplained alert had never been seen by the linter that gates the build.
  Found on 2026-10-02 by running ruff over the whole tree by hand while working on
  something else, which is not a way of finding things that scales.

- **The Italian comments are in English** — `Dockerfile`, `docker.yml`,
  `checker.py`, `cli.py`, `discover.py`, `gpg.py` and three test files. One
  comment in `docker.yml` had been half translated and ended mid-sentence.

- **The Docker build no longer races its own publish.** `docker.yml` and
  `publish.yml` both fire on the tag push, in parallel, and the Dockerfile
  installs `mailradar==<new version>` from PyPI. A fixed `sleep 60` stood in for
  the wait.

  mailradar never went red on it, which is exactly why this is here: apkradar had
  the identical step and lost the race twice — 2026.9.32 on 2026-09-24 and
  v2026.41 on 2026-09-30 — while mailradar published in the same minutes of the
  second one and passed on timing alone. The failure reads as
  `No matching distribution found`, listing versions up to the *previous*
  release, so it looks like a failed publish when PyPI already holds the files
  and only the index has not caught up.

  `.github/scripts/wait_for_pypi.sh` now polls with pip itself, which is what the
  Dockerfile uses and what the index answers for, for up to ten minutes. It runs
  *after* the version is extracted rather than before, because the tag is
  `v2026.41` while the distribution is `2026.41` and `==v2026.41` is not a
  version pip can ever find — where the `sleep` sat, there was nothing to wait
  for by name. Only on a tag push: the weekly rebuild of `latest` and a manual
  dispatch both name a version published long ago. Ported from cookieradar, which
  has polled since 2026-09-24, with its tests — `tests/test_ci_scripts.py` drives
  the script with a fake pip and pins where the step sits, what version it is
  given, and that nothing in the workflow waits by sleeping again.

## [2026.41] - 2026-09-29

### Fixed

- **The report no longer ends with a traceback.** Rich wraps `sys.stdout` in a
  `FileProxy` while a spinner runs and restores the stream without flushing it, so
  a partial line sat in that buffer until the proxy was garbage-collected — often
  during interpreter shutdown, where the message is
  `ImportError: sys.meta_path is None`. It appeared after a completed analysis, on
  a terminal only, and looked like the software failing at the worst possible
  moment. All eight spinners now flush both streams before they stop.

- **One pull request per CodeQL upgrade, not four.** The four `codeql-action`
  steps are pinned to a commit here, and Dependabot treats each path as its own
  dependency: on 2026-09-29 it opened #18, #19, #21 and #22 for the same
  4.38.1 → 4.38.2 bump, and every one failed with "Loaded a configuration file for
  version '4.38.1', but running version '4.38.2'" — each moved one step and left
  three behind, while CodeQL requires them to match. All four are on 4.38.2 now,
  and a `groups` entry keeps them moving together. mailradar was the only Radar
  exposed: the other four track the moving `@v4` tag, which hides the skew.

### Added

- **A CI gate that refuses.** Every other security workflow reports: `snyk.yml`
  carries `continue-on-error`, CodeQL and Docker Scout upload SARIF, and
  SonarCloud decides its quality gate after the job has already succeeded. On
  2026-09-29 all of them were green while ten high-severity alerts were open.
  `security-posture.yml` reads what they published and fails when a blocking
  finding has nobody's name against it; `SECURITY-EXCEPTIONS.toml` records the
  accepted ones, each with a reason and a review date. `sonarcloud.yml` now waits
  for its own quality gate, without which a red gate is a green job.

### Changed

- The prose is in English throughout. The quoted law stays in Italian, because
  that is the language it is read in.

## [2026.40] - 2026-09-26

### Changed

- **Nothing in the shipped package.** `mailradar/` is byte-identical to
  2026.09.12: no behaviour changes, no fixes, nothing to upgrade for. This
  version exists because the five Radar restarted from a common baseline, and a
  baseline that skips whoever had nothing to say would not be one. It is said
  here rather than left to be guessed from an empty diff.

- **Baseline: the five Radar restart from a common number.** They had drifted to
  .32, .12, .11, .6 and .3 of the same generation, which left the shared part of
  the version meaning nothing at all. The highest count in the suite was taken,
  rounded up for headroom, and every Radar starts again from 2026.40. From here
  the count belongs to each Radar again, and something urgent gets a third
  segment on top: 2026.40.1 before 2026.41.

- **The workflow named Tests now runs the tests.** It contained no pytest
  invocation: it installed the package and ran three CLI commands, two of them
  against a live domain, so the check required on every pull request depended on
  DNS and on somebody else's mail server. The suite was running inside
  `sonarcloud.yml`, on 3.12 only, which meant the four-version matrix here was
  proving that `mailradar --help` exits zero on four versions.

- PyYAML is declared. The tests read the workflow files and had been borrowing
  it from `mutmut` -> `libcst`, which on Python 3.13 requires `pyyaml-ft`
  instead — a fork that installs no module called `yaml`.

## [2026.09.12] - 2026-09-24

### Fixed
- **`mailradar batch` reads its list of domains as UTF-8.** It used a bare
  `open(file)`, so the locale chose the encoding. An internationalised domain is
  the ordinary case here, not an exotic one — `società.it` and `müller.de` are
  both registrable — and read through cp1252 the query went to a domain that
  does not resolve, reported as though it had been the one asked for. Three more
  defects in the same four lines: a byte order mark, which Notepad writes by
  default, became part of the first domain; an `OSError` that is not
  `FileNotFoundError` escaped as a traceback; and `#` was tested against the
  unstripped line, so an **indented comment was queried as a domain**.
- **One `GPGResult`, not two.** The class was declared in both `checker.py` and
  `gpg.py`, and the two were not the same: `gpg.py`'s carries a `fingerprint`
  field the other lacked. Since `lookup_gpg` returns `gpg.py`'s, a scanned
  `DomainReport` and a default-built one held different shapes in the same
  field. The duplicate is removed.
- **An unverifiable law now says what it costs.** The report warned that an act
  could not be fetched and separately printed `SHA256: non disponibile` against
  each citation, with nothing joining the two, so a missing hash read as a
  defect in the hashing. It is not: with no verified text there is nothing to
  hash.
- **`MAILRADAR_HOME` is no longer taken literally.** `~/cache` made a directory
  named `~`, a relative value followed the working directory so the cache
  stopped being one cache, and `"   "` became a directory name.
- `_discover_via_website` declared `extra_subdomains: list[str]` and defaulted
  it to `None`. The GPG lookup now pairs addresses with results under
  `strict=True`: `executor.map` yields one result per input, so the lengths are
  equal by construction, and this checks it rather than assuming it.

### Changed
- ruff, mypy, hypothesis and mutmut are development dependencies, with a
  `Quality` workflow running ruff and mypy on every push and pull request, and a
  weekly, non-blocking mutation run.
- Fifteen new properties checked against generated input: the DMARC and BIMI tag
  parsers read a string a domain owner writes by hand, and the email extractor is
  checked against its near-misses — `example.community` and
  `example.com.evil.org` must not match `example.com`.
- A contract test refuses any code in this repository that lets the locale
  choose a text encoding.
- **Every string the tool writes itself is now in English**, which the
  CHANGELOGs already were. The report's section is `Provisions applied` rather
  than `Norme applicate`, and finding titles, scope notes, evidence lines and
  the release script's messages follow. What the tool *quotes* is unchanged: a
  provision's text is fetched from the official Italian version of each act and
  hashed, so translating it would change every SHA-256 in every cache and report
  "the law changed" for every citation on the next run, for nothing.

## [2026.09.11] - 2026-09-21

### Fixed
- DMARC lookup walks up the domain hierarchy as required by RFC 7489 §6.6.3:
  when `_dmarc.<domain>` has no record, one label is removed at a time up to
  the organizational domain (`asufc.sanita.fvg.it` → `sanita.fvg.it` →
  `fvg.it`). Multi-label public suffixes such as `co.uk` are honoured, and the
  public suffix itself is never queried. An inherited record is reported with
  the domain it comes from, and the parent's `sp=` tag becomes the policy
  scored for the subdomain.

## [2026.09.10] - 2026-09-19

### Added
- `check` and `report` end with a "Provisions applied" section: each weakness
  cites the legal provisions it concerns, with the SHA-256 of the exact text
  applied and the date of that wording. The text is downloaded from EUR-Lex on
  every run and cached in `~/.mailradar/law_cache.json` (`MAILRADAR_HOME`
  moves the folder); a changed text is reported with its previous hash.
  Offline the cached copy is cited, or "SHA256: non disponibile". A failed law
  check never changes the result or the exit code.
  - GDPR art. 32: DMARC missing, weak SPF/DKIM, no GPG key on keyservers;
    art. 32(1)(a): MTA-STS missing or not enforced (mail may travel in clear).
  - NIS2, directive (EU) 2022/2555, art. 21: DMARC missing or MTA-STS missing
    (not for MTA-STS in testing mode). The report notes that NIS2 applies to
    essential and important entities only.

## [2026.09.9] - 2026-09-19

### Added
- `--version` option: `mailradar --version` prints `MailRadar <version>` and exits.
  The version is read from `mailradar.__version__`, the single source of truth
  also used by `pyproject.toml`.

### Fixed
- Docker: the `latest` image is now rebuilt every week from the most recent tag,
  without cache and pulling a fresh base image, so Debian security patches are
  picked up without waiting for a release. Versioned images are left unchanged.

### Security
- Docker: pip is upgraded before installing MailRadar and then removed from the
  final image. It is not needed at runtime and its vendored dependencies had
  known CVEs.
- `SECURITY.md`: the known open CVEs are now attributed to the correct base
  image (Debian Trixie) and the list was updated (OpenSSL is no longer
  affected).

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

[Unreleased]: https://github.com/maksimtech/mailradar/compare/v2026.09.11...HEAD
[2026.09.11]: https://github.com/maksimtech/mailradar/compare/v2026.09.10...v2026.09.11
[2026.09.10]: https://github.com/maksimtech/mailradar/compare/v2026.09.9...v2026.09.10
[2026.09.9]: https://github.com/maksimtech/mailradar/compare/v2026.09.8...v2026.09.9
[2026.09.8]: https://github.com/maksimtech/mailradar/compare/v2026.09.7...v2026.09.8
[2026.09.7]: https://github.com/maksimtech/mailradar/compare/v2026.09.6...v2026.09.7
[2026.09.6]: https://github.com/maksimtech/mailradar/compare/v2026.09.5...v2026.09.6
[2026.09.5]: https://github.com/maksimtech/mailradar/compare/v2026.09.4...v2026.09.5
[2026.09.4]: https://github.com/maksimtech/mailradar/compare/v2026.09.3...v2026.09.4
[2026.09.3]: https://github.com/maksimtech/mailradar/compare/v2026.09.2...v2026.09.3
[2026.09.2]: https://github.com/maksimtech/mailradar/compare/v2026.09.1...v2026.09.2
[2026.09.1]: https://github.com/maksimtech/mailradar/releases/tag/v2026.09.1
