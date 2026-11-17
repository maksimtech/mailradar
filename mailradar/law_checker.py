"""
MailRadar — EU and Italian law provisions for audit findings.

Maps what an audit found to the provisions it concerns, and cites each one
with the SHA-256 of the exact text applied and the date of that wording. The
text is downloaded on every audit (EUR-Lex, or Normattiva for Italian law)
and compared with the local cache; without network the cached copy is cited.

Shared by the Radar tools: only the mapping section is specific to MailRadar.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from mailradar import law_fetcher
from mailradar.law_cache import Key, LawCache, merge
from mailradar.law_fetcher import DLGS_138_2024, GDPR, Act, LawFetchError, Provision

# ─── Mapping: MailRadar findings → provisions ─────────────────────────────────

# Finding → cited provisions, in report order
FINDING_ARTICLES = {
    "dmarc_missing": ((GDPR, "32"), (DLGS_138_2024, "24")),
    "spf_dkim_weak": ((GDPR, "32"),),
    "cleartext": ((GDPR, "32(1)(a)"), (DLGS_138_2024, "24")),     # MTA-STS absent
    "cleartext_testing": ((GDPR, "32(1)(a)"),),            # MTA-STS not enforced
}

FINDING_TITLES = {
    "dmarc_missing": "DMARC missing",
    "spf_dkim_weak": "SPF/DKIM weak",
    "cleartext": "Cleartext delivery possible",
    "cleartext_testing": "Cleartext delivery possible",
}

# Articles downloaded and cached even when not cited, by act
ALSO_FETCH: dict = {}

# No published GPG key is a suggestion, not a gap: GDPR art. 32 asks for
# measures appropriate to the risk, and none of them is a key on a keyserver
# (owner's decision, 2026-11-17). Until then it was cited as art. 32.
GPG_SUGGESTION = (
    "No public GPG key for the domain's contact addresses: publishing one (keys.openpgp.org) lets "
    "security reports reach it encrypted — a suggestion, not a legal requirement"
)

NIS2_SCOPE_NOTE = (
    "D.Lgs. 138/2024 art. 24 binds essential and important entities (art. 3 of the decree): "
    "check that the domain holder falls within scope"
)

# Below this a DKIM key counts as weak (MailRadar's own threshold for full score)
DKIM_MIN_BITS = 2048


def findings_of(report) -> dict[str, list[str]]:
    """
    Findings in a MailRadar DomainReport, with what triggered each.

    "Invio in chiaro": without MTA-STS in enforce mode a sending server may
    fall back to unencrypted SMTP, or be downgraded to it by an attacker.
    """
    found: dict[str, list[str]] = {}

    # A check whose DNS lookup failed (`error`) is neither missing nor weak
    if not report.dmarc.present and not report.dmarc.error:
        found["dmarc_missing"] = ["no DMARC record"]

    weak = []
    if not report.spf.present:
        if not report.spf.error:
            weak.append("no SPF record")
    elif report.spf.permerror:
        weak.append("SPF permerror: receivers apply no SPF")
    elif report.spf.permissive:
        weak.append(f"SPF {report.spf.all_mechanism or 'permissivo'}")
    # A key under none of the common selectors is not found, not absent: DNS
    # cannot list selectors, and amazon.it signs under its own. Only a key
    # that was found, and is short, is a weakness worth citing.
    if report.dkim.present and report.dkim.key_type == "rsa" and report.dkim.key_bits < DKIM_MIN_BITS:
        weak.append(f"DKIM {report.dkim.key_bits} bit")
    if weak:
        found["spf_dkim_weak"] = weak

    if not report.mta_sts.present:
        if not report.mta_sts.error:
            found["cleartext"] = ["MTA-STS missing: TLS not mandatory on delivery"]
    elif report.mta_sts.mode != "enforce":
        found["cleartext_testing"] = [f"MTA-STS in {report.mta_sts.mode or 'unknown'} mode, not enforce"]

    return {finding: found[finding] for finding in FINDING_ARTICLES if finding in found}


def notes_of(report) -> list[str]:
    # From the findings, so that the note goes with the citation: a DMARC or
    # MTA-STS lookup that failed cites nothing, and used to get the note anyway
    cites_nis2 = any(
        act == DLGS_138_2024
        for finding in findings_of(report)
        for act, _ in FINDING_ARTICLES[finding]
    )
    notes = [NIS2_SCOPE_NOTE] if cites_nis2 else []
    # A keyserver that did not answer (rate limit, timeout) proved nothing
    if not report.gpg.found and not report.gpg.error:
        notes.append(GPG_SUGGESTION)
    return notes


# ─── Citations ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Citation:
    finding: str
    law: str                      # act as cited: "GDPR"
    article: str                  # "32(1)(a)"
    sha256: str | None         # None when the text could not be obtained
    version_date: str | None   # YYYY-MM-DD the wording was downloaded


@dataclass(frozen=True)
class ActStatus:
    act: Act
    # "verified": every reference cited was in the text downloaded now; "cache": the source was
    # unreachable or its text lacked a reference, cached copy; "unavailable": no text at all
    source: str
    error: str | None = None
    # Where a verified text came from: "Cellar", "EUR-Lex" (the fallback) or "Normattiva"; None otherwise
    origin: str | None = None
    # When not verified: the source tried last ("Cellar", "EUR-Lex", "Normattiva", "Cellar and
    # EUR-Lex"; None if unknown), and why it was not used: "unreachable" (no page) or "not_in_text"
    # (a page, without the text cited)
    tried: str | None = None
    failure: str | None = None

    @property
    def reason(self) -> str | None:
        """Why the act was not verified, as a report says it: "Cellar and EUR-Lex unreachable"."""
        if self.source == "verified":
            return None
        tried = self.tried or self.act.source
        if self.failure == "not_in_text":
            return f"{tried} answered without the text cited"
        return f"{tried} unreachable"


@dataclass
class LawCheckResult:
    citations: list[Citation]
    acts: list[ActStatus] = field(default_factory=list)
    # What triggered each finding, e.g. {"critical": ["CVE-2026-1234"]}
    evidence: dict[str, list[str]] = field(default_factory=dict)
    # "GDPR art. 32" → SHA-256 of its previous text, for cited provisions
    # whose text changed since the last audit
    changed: dict[str, str] = field(default_factory=dict)
    # Remarks without a citation, e.g. why no verdict was possible
    notes: list[str] = field(default_factory=list)


def check(
    subject,
    *,
    cache: LawCache | None = None,
    now: datetime | None = None,
    client: httpx.Client | None = None,
    **context,
) -> LawCheckResult:
    """
    Cite the provisions that apply to the findings about `subject`.

    `context` is passed on to findings_of and notes_of: what the audit found
    besides `subject` itself.
    """
    evidence = findings_of(subject, **context)
    notes = notes_of(subject, **context)
    cited = [
        (finding, act, ref)
        for finding in evidence
        for act, ref in FINDING_ARTICLES[finding]
    ]
    if not cited:
        return LawCheckResult(citations=[], notes=notes)

    cache = cache or LawCache()
    now = now or datetime.now(UTC)

    acts = list(dict.fromkeys(act for _, act, _ in cited))
    # Keyed by (celex, article) — the cache's key, not the fetcher's.
    fresh: dict[Key, Provision] = {}
    errors: dict[Act, LawFetchError] = {}
    origins: dict[Act, str] = {}
    for act in acts:
        refs = list(dict.fromkeys(ref for _, a, ref in cited if a == act))
        # The articles cited ("32(1)(a)" is part of article 32) and ALSO_FETCH
        articles = tuple(dict.fromkeys(
            [ref.split("(")[0] for ref in refs] + list(ALSO_FETCH.get(act, ()))
        ))
        try:
            by_article, origin = law_fetcher.fetch_provisions_from(act, articles, now=now, client=client)
            # The article being there is not enough: each reference cited is
            # checked against the text just parsed. A point the parser missed
            # used to fall back to the cache, old hash and date included, under
            # the "verified" label, or to no hash at all.
            missing = [ref for ref in refs if ref not in by_article]
            if missing:
                raise LawFetchError(
                    f"{act.name} art. {', '.join(missing)} not found in the text from {origin}",
                    source=origin, reached=True,
                )
        except LawFetchError as e:
            errors[act] = e
        else:
            origins[act] = origin
            fresh.update({p.key: p for p in by_article.values()})

    # Merged here, not by the save: a cache that cannot be written (read-only,
    # disk full) must not hide a change in the law, nor date an unchanged
    # wording to today.
    provisions, changed = merge(cache.load(), fresh)
    if fresh:
        # Unsaved, the text just downloaded can still be cited
        with contextlib.suppress(OSError):
            cache.update(fresh, checked_at=law_fetcher.utc_stamp(now))

    statuses = []
    for act in acts:
        if act not in errors:
            statuses.append(ActStatus(act, "verified", origin=origins[act]))
        else:
            error = errors[act]
            cached = any((act.celex, ref) in provisions for _, a, ref in cited if a == act)
            statuses.append(ActStatus(
                act, "cache" if cached else "unavailable", str(error),
                tried=error.source, failure="not_in_text" if error.reached else "unreachable",
            ))

    citations = []
    for finding, act, ref in cited:
        provision = provisions.get((act.celex, ref))
        citations.append(Citation(
            finding=finding,
            law=act.name,
            article=ref,
            sha256=provision.sha256 if provision else None,
            version_date=provision.fetched_at[:10] if provision else None,
        ))

    names = {act.celex: act.name for act in acts}
    cited_keys = {(act.celex, ref) for _, act, ref in cited}
    return LawCheckResult(
        citations=citations,
        acts=statuses,
        evidence=evidence,
        changed={
            f"{names[celex]} art. {article}": sha
            for (celex, article), sha in changed.items()
            if (celex, article) in cited_keys
        },
        notes=notes,
    )


def format_citation(citation: Citation) -> str:
    return (
        f"Provision applied: {citation.law} art. {citation.article}\n"
        f"SHA256: {citation.sha256 or 'not available'}\n"
        f"Version of: {citation.version_date or 'not available'}"
    )
