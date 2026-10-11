# Security Policy

## Reporting a vulnerability

Write to <security@maksimtech.com>; the GPG key for that address is on
keys.openpgp.org. Please do not open a public issue for a vulnerability.

MailRadar has a single maintainer, Massimo Moretti, who reads that address.

## Supported versions

Only the latest release receives fixes. Versions follow CalVer (`YYYY.count[.fix]`):
a fix ships as the next release, never as a patch to an older one.

## How vulnerabilities are found

- **CodeQL, Bandit and Trivy** (repository files) run on every pull request, on
  every push to `main` and weekly.
- **Snyk** checks the dependencies on every pull request and push to `main`.
- **Docker Scout** checks the image on every push to `main`, on every image build
  and weekly. The image is built on `python:3.12-slim-trixie` (Debian Trixie), and
  `latest` is rebuilt weekly to pick up Debian's security patches.
- **Security Posture** reads the alerts all of the above publish to GitHub code
  scanning and fails when a high or critical finding has no reasoned exception in
  `SECURITY-EXCEPTIONS.toml`. It also runs weekly, because an exception expires by
  date and not by commit.
- Reports sent to the address above.

## Response times

- A fix ships with the next release. Releases can be up to a month apart.
- For a vulnerability with a CVSS score of 9.0 or more, customers who have given a
  security contact are told within 48 hours of the report being taken in charge,
  even if the fix is not ready yet.
- A vulnerability that is accepted rather than fixed is recorded in
  `SECURITY-EXCEPTIONS.toml` with the reason and a review date; Security Posture
  fails once the review date has passed.

## Customer notification

Every fix is described in the release notes on GitHub, which are the CHANGELOG
section of that version. For a vulnerability with a CVSS score of 9.0 or more,
customers who have given a security contact also get a direct email.

## Rollback

Every version stays installable and pinnable:

- PyPI: `pip install mailradar==<version>`;
- Docker Hub: `maksimtech/mailradar:v<version>`, a tag the weekly rebuild of
  `latest` does not overwrite, and the SHA256 digest of that image, which cannot
  change.

Rolling back means pinning the previous version or digest. Releases are cut with
`release.sh`.

## Evidence attached to every release

Each GitHub release carries CycloneDX SBOMs of the image and of the Python
environment, and dated Trivy reports of the image and of the repository at the
tag. The Trivy reports are an automated scan for known vulnerabilities, not a
penetration test; no penetration test has been carried out. What these files are,
and the answers to the questions a customer subject to NIS2 may ask, are in
[docs/nis2-compliance.md](docs/nis2-compliance.md).

Last reviewed: 2026-10-11
