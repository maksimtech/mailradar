# Changelog

All notable changes to MailRadar are documented here.

Format: [YYYY.MM.PATCH] — CalVer versioning

---

## [2026.09.1] — 2026-09-04

### Added
- Core email security checker (DMARC, SPF, DKIM, BIMI, MTA-STS, TLS-RPT)
- Accurate DKIM key size detection via `cryptography` library
- Scoring system 0-100 with grade levels (EXCELLENT/GOOD/MODERATE/POOR/CRITICAL)
- CLI with `check` and `batch` commands
- Rich terminal output with color-coded results
- Issue reporting with actionable recommendations
- Multi-selector DKIM detection (common selectors)
- BIMI SVG validation via HTTP
- MTA-STS policy mode detection
