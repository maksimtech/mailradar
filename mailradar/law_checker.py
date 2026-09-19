"""
MailRadar — EU and Italian law provisions for audit findings.

Maps what an audit found to the provisions it concerns, and cites each one
with the SHA-256 of the exact text applied and the date of that wording. The
text is downloaded on every audit (EUR-Lex, or Normattiva for Italian law)
and compared with the local cache; without network the cached copy is cited.

Shared by the Radar tools: only the mapping section is specific to MailRadar.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from mailradar import law_fetcher
from mailradar.law_cache import LawCache
from mailradar.law_fetcher import GDPR, NIS2, Act, LawFetchError

# ─── Mapping: MailRadar findings → provisions ─────────────────────────────────

# Finding → cited provisions, in report order
FINDING_ARTICLES = {
    "dmarc_missing": ((GDPR, "32"), (NIS2, "21")),
    "spf_dkim_weak": ((GDPR, "32"),),
    "cleartext": ((GDPR, "32(1)(a)"), (NIS2, "21")),     # MTA-STS absent
    "cleartext_testing": ((GDPR, "32(1)(a)"),),            # MTA-STS not enforced
    "gpg_missing": ((GDPR, "32"),),
}

FINDING_TITLES = {
    "dmarc_missing": "DMARC assente",
    "spf_dkim_weak": "SPF/DKIM deboli",
    "cleartext": "Invio in chiaro possibile",
    "cleartext_testing": "Invio in chiaro possibile",
    "gpg_missing": "GPG non disponibile",
}

# Articles downloaded and cached even when not cited, by act
ALSO_FETCH: dict = {}

NIS2_SCOPE_NOTE = (
    "NIS2 art. 21 obbliga i soggetti essenziali e importanti (art. 3 della direttiva): "
    "verificare che il titolare del dominio rientri nell'ambito"
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

    if not report.dmarc.present:
        found["dmarc_missing"] = ["nessun record DMARC"]

    weak = []
    if not report.spf.present:
        weak.append("nessun record SPF")
    elif report.spf.permissive:
        weak.append(f"SPF {report.spf.all_mechanism or 'permissivo'}")
    if not report.dkim.present:
        weak.append("nessuna chiave DKIM con i selettori comuni")
    elif report.dkim.key_bits < DKIM_MIN_BITS:
        weak.append(f"DKIM {report.dkim.key_bits} bit")
    if weak:
        found["spf_dkim_weak"] = weak

    if not report.mta_sts.present:
        found["cleartext"] = ["MTA-STS assente: TLS non obbligatorio in ricezione"]
    elif report.mta_sts.mode != "enforce":
        found["cleartext_testing"] = [f"MTA-STS in modalità {report.mta_sts.mode or 'sconosciuta'}, non enforce"]

    if not report.gpg.found:
        found["gpg_missing"] = ["nessuna chiave pubblica sui keyserver"]

    return {finding: found[finding] for finding in FINDING_ARTICLES if finding in found}


def notes_of(report) -> list[str]:
    cites_nis2 = not report.dmarc.present or not report.mta_sts.present
    return [NIS2_SCOPE_NOTE] if cites_nis2 else []


# ─── Citations ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Citation:
    finding: str
    law: str                      # act as cited: "GDPR"
    article: str                  # "32(1)(a)"
    sha256: Optional[str]         # None when the text could not be obtained
    version_date: Optional[str]   # YYYY-MM-DD the wording was downloaded


@dataclass(frozen=True)
class ActStatus:
    act: Act
    # "verified": downloaded now from the act's source (EUR-Lex or Normattiva);
    # "cache": source unreachable, cached copy; "unavailable": no text at all
    source: str
    error: Optional[str] = None


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
    cache: Optional[LawCache] = None,
    now: Optional[datetime] = None,
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
    now = now or datetime.now(timezone.utc)

    acts = list(dict.fromkeys(act for _, act, _ in cited))
    fresh = {}
    errors = {}
    for act in acts:
        # The articles cited ("32(1)(a)" is part of article 32) and ALSO_FETCH
        articles = tuple(dict.fromkeys(
            [ref.split("(")[0] for _, a, ref in cited if a == act] + list(ALSO_FETCH.get(act, ()))
        ))
        try:
            provisions = law_fetcher.fetch_provisions(act, articles, now=now)
        except LawFetchError as e:
            errors[act] = str(e)
        else:
            fresh.update({p.key: p for p in provisions.values()})

    changed = {}
    try:
        if fresh:
            provisions, changed = cache.update(fresh, checked_at=law_fetcher.utc_stamp(now))
        else:
            provisions = cache.load()
    except OSError:
        provisions = {**cache.load(), **fresh}   # the text just downloaded can still be cited

    statuses = []
    for act in acts:
        if act not in errors:
            statuses.append(ActStatus(act, "verified"))
        else:
            cached = any((act.celex, ref) in provisions for _, a, ref in cited if a == act)
            statuses.append(ActStatus(act, "cache" if cached else "unavailable", errors[act]))

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
        f"Norma applicata: {citation.law} art. {citation.article}\n"
        f"SHA256: {citation.sha256 or 'non disponibile'}\n"
        f"Versione del: {citation.version_date or 'non disponibile'}"
    )
