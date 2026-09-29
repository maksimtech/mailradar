"""
MailRadar — a green pipeline must mean a clean product.

On 2026-09-28 every workflow was green while SonarCloud's quality gate was red
and thirteen high-severity alerts were open in code scanning. Nothing was
broken: `snyk.yml` carries `continue-on-error` by design so a pull request is not
blocked by pre-existing findings, and Sonar evaluates its gate after the job has
already succeeded. The result is a pipeline that reports and never refuses.

This is the gate that refuses. Its rule is the one that can be defended:

    block on everything we can fix; never block on an upstream flaw with no fix
    available — but require a dated, written reason for each one.

That is stricter than "wait until it is fixed", not laxer. Waiting on
`CVE-2026-85091` in Debian's zlib, which upstream marks "not fixed", means never
releasing our own fixes again; and an unexplained finding that nobody has to
justify is how thirteen of them came to be open without anyone deciding.

Three ways to fail, and the third is the one that keeps the file honest:

  - an open high or critical alert with no exception covering it;
  - an exception whose review date has passed;
  - an exception that no longer matches anything, so the file stops describing
    the product.
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import pathlib
import sys

import pytest

# Loaded by path, the way tests/test_snyk_tools.py loads its own: `tools/` is a
# directory of scripts the CI runs, not a package, and importing it as one would
# declare a dependency this project does not have.
_TOOLS = pathlib.Path(__file__).resolve().parent.parent / "tools"
_spec = importlib.util.spec_from_file_location(
    "security_exceptions", _TOOLS / "security_exceptions.py"
)
security_exceptions = importlib.util.module_from_spec(_spec)
# Registered before it runs, not after. A frozen dataclass whose annotations are
# postponed by `from __future__ import annotations` makes `dataclasses` look its
# own module up in `sys.modules` to resolve them; a module loaded by spec and not
# registered is not there, and the decorator dies on
# `'NoneType' object has no attribute '__dict__'` at import time.
sys.modules[_spec.name] = security_exceptions
_spec.loader.exec_module(security_exceptions)

Exception_ = security_exceptions.Exception_
Verdict = security_exceptions.Verdict
load_exceptions = security_exceptions.load_exceptions
review = security_exceptions.review

TODAY = dt.date(2026, 9, 29)


def alert(number: int, rule: str, *, severity: str = "high", tool: str = "Docker Scout") -> dict:
    """One code-scanning alert, shaped as the GitHub API returns it."""
    return {
        "number": number,
        "rule": {"id": rule, "security_severity_level": severity},
        "tool": {"name": tool},
        "most_recent_instance": {"location": {"path": "Dockerfile", "start_line": 1}},
    }


def allowed(rule: str, *, source: str = "Docker Scout", review_by: str = "2026-12-31",
            path: str | None = None) -> Exception_:
    return Exception_(id=rule, source=source, where="somewhere", why="a reason",
                      review_by=review_by, path=path)


# ── an alert nobody explained ───────────────────────────────────────────────

def test_an_unexplained_high_alert_fails():
    verdict = review([alert(1, "CVE-2026-85091")], [], today=TODAY)

    assert not verdict.ok
    assert [a["number"] for a in verdict.unexplained] == [1]


def test_an_explained_alert_passes():
    verdict = review([alert(1, "CVE-2026-85091")], [allowed("CVE-2026-85091")], today=TODAY)

    assert verdict.ok
    assert verdict.unexplained == []


@pytest.mark.parametrize("severity", ["note", "warning", "medium", "low", None])
def test_only_high_and_critical_block(severity):
    """The ten `note` findings of 2026-09-28 were all false positives — a path
    traversal whose source is the operator's own environment variable, a test
    harness, an XML parser rule that names Python versions this project does not
    support. Demanding a written exception for each would fill the file with
    noise and teach whoever reads it to skim."""
    verdict = review([alert(1, "python/PT", severity=severity)], [], today=TODAY)

    assert verdict.ok


def test_critical_blocks_like_high():
    verdict = review([alert(1, "X", severity="critical")], [], today=TODAY)
    assert not verdict.ok


def test_the_source_has_to_match_too():
    """The same CVE id can be reported by two scanners about two different
    things. An exception written for one does not cover the other."""
    scout = [alert(1, "CVE-2026-85091", tool="Docker Scout")]
    for_snyk = [allowed("CVE-2026-85091", source="Snyk Container")]

    assert not review(scout, for_snyk, today=TODAY).ok
    assert review(scout, [allowed("CVE-2026-85091", source="Docker Scout")], today=TODAY).ok


def test_an_exception_without_a_source_covers_any_scanner():
    """Deliberate: some findings are reported by whichever tool looks first, and
    pinning the tool would make the record fail for the wrong reason."""
    entry = Exception_(id="CVE-1", source=None, where="w", why="y", review_by="2026-12-31")
    assert review([alert(1, "CVE-1", tool="Anything")], [entry], today=TODAY).ok


def test_a_path_narrows_an_exception_to_the_file_it_was_written_about():
    """A CodeQL rule can fire anywhere. An entry for
    `py/clear-text-logging-sensitive-data` in `api/main.py` must not excuse the
    next real one in a collector."""
    here = alert(1, "py/clear-text-logging-sensitive-data", tool="CodeQL")
    elsewhere = alert(2, "py/clear-text-logging-sensitive-data", tool="CodeQL")
    elsewhere["most_recent_instance"]["location"]["path"] = "mailradar/checker.py"
    entry = allowed("py/clear-text-logging-sensitive-data", source="CodeQL", path="Dockerfile")

    assert review([here], [entry], today=TODAY).ok
    assert not review([elsewhere], [entry], today=TODAY).ok


def test_without_a_path_an_exception_does_not_care_where_the_alert_is():
    """Right for a CVE: the location is the image, not a line of ours."""
    entry = allowed("CVE-1", path=None)
    moved = alert(1, "CVE-1")
    moved["most_recent_instance"]["location"]["path"] = "anywhere"
    assert review([moved], [entry], today=TODAY).ok


# ── an exception nobody reviewed ────────────────────────────────────────────

def test_an_expired_exception_fails_even_when_everything_else_is_quiet():
    """The date is the whole point. Without it an exception is a way of never
    looking again."""
    verdict = review([], [allowed("CVE-1", review_by="2026-09-28")], today=TODAY)

    assert not verdict.ok
    assert [e.id for e in verdict.expired] == ["CVE-1"]


def test_the_review_date_is_inclusive():
    """Reviewed today is reviewed."""
    assert review([], [allowed("CVE-1", review_by="2026-09-29")], today=TODAY).ok


def test_an_expired_exception_still_covers_its_alert():
    """Both things are wrong at once and both are reported: the alert is
    explained, and the explanation is overdue. Hiding the second behind the
    first is how an exception becomes permanent."""
    verdict = review([alert(1, "CVE-1")], [allowed("CVE-1", review_by="2026-01-01")], today=TODAY)

    assert verdict.unexplained == []
    assert len(verdict.expired) == 1
    assert not verdict.ok


# ── an exception that describes nothing ─────────────────────────────────────

def test_an_exception_matching_nothing_fails_once_its_scanner_has_spoken():
    """The five vendored copies of 2026-09-28 will disappear when the next image
    is published. Their exceptions must then fail, or the file keeps claiming a
    problem the product no longer has — and the next reader trusts it less."""
    verdict = review([alert(1, "CVE-OTHER", tool="Docker Scout")],
                     [allowed("CVE-GONE", source="Docker Scout")], today=TODAY)

    assert [e.id for e in verdict.unused] == ["CVE-GONE"]
    assert not verdict.ok


def test_an_exception_is_not_unused_when_its_scanner_reported_nothing_at_all():
    """A scan that failed to upload produces an empty list, and an empty list is
    not a clean product. Calling every exception stale there would fail the
    build for the one reason that is not the product's fault."""
    # The CodeQL alert is a `note` on purpose: this test is about `unused`, and a
    # blocking alert with no entry would fail the verdict for the other reason.
    verdict = review([alert(1, "X", tool="CodeQL", severity="note")],
                     [allowed("CVE-1", source="Docker Scout")], today=TODAY)

    assert verdict.unused == []
    assert verdict.ok


def test_a_sourceless_exception_is_only_unused_when_some_alert_exists():
    entry = Exception_(id="CVE-1", source=None, where="w", why="y", review_by="2026-12-31")

    assert review([], [entry], today=TODAY).ok, "nothing reported, nothing to conclude"
    assert not review([alert(1, "OTHER")], [entry], today=TODAY).ok


# ── a finding that came and went ────────────────────────────────────────────
#
# Measured on 2026-09-29, and the reason this section exists. Docker Scout
# reported CVE-2026-82560 against all five Radar, then stopped reporting it
# against exeradar at 15:08 — GitHub marked that alert `state: fixed`, nobody
# having dismissed it. The published image had not changed. patchradar and
# mailradar carry the same CVE both open *and* closed: it had already gone and
# come back once, on 2026-09-28.
#
# So a scanner dropping a finding for one run is not evidence that the finding is
# gone, and the first version of this tool failed the build for it — then failed
# it again, for "unexplained", once the entry was deleted and Scout changed its
# mind back. An oscillation that demands alternating commits is worse than no
# rule at all, because the way out is to stop reading the output.
#
# What separates the two cases is whether GitHub has the finding at all. An entry
# matching an alert that is closed describes something real that was reported
# recently; an entry matching nothing in any state is drift, and that is what the
# rule was written for.

def test_an_exception_whose_finding_is_only_closed_does_not_fail_the_build():
    """Scout dropped it this run. The entry is reported, not condemned."""
    verdict = review([alert(1, "OTHER", severity="note")], [allowed("CVE-2026-82560")],
                     today=TODAY, closed=[alert(9, "CVE-2026-82560")])

    assert verdict.unused == [], "a closed finding is not a stale entry"
    assert [e.id for e in verdict.settled] == ["CVE-2026-82560"]
    assert verdict.ok, "worth saying, not worth failing"


def test_an_exception_matching_nothing_in_any_state_still_fails():
    """The rule keeps its teeth. Nothing open, nothing closed: the record
    describes something this repository does not have."""
    verdict = review([alert(1, "OTHER", severity="note")], [allowed("CVE-1")],
                     today=TODAY, closed=[alert(9, "SOMETHING-ELSE")])

    assert not verdict.ok
    assert [e.id for e in verdict.unused] == ["CVE-1"]
    assert verdict.settled == []


def test_a_settled_entry_is_named_and_the_flapping_is_explained():
    verdict = review([alert(1, "OTHER", severity="note")], [allowed("CVE-2026-82560")],
                     today=TODAY, closed=[alert(9, "CVE-2026-82560")])
    said = verdict.describe()

    assert "CVE-2026-82560" in said
    assert "not reported" in said.lower() or "no longer" in said.lower()


def test_closed_alerts_are_matched_by_source_like_open_ones():
    """A Snyk entry is not settled by Scout having closed the same CVE: the two
    scanners disagree about this package routinely, and one going quiet says
    nothing about the other."""
    entry = allowed("CVE-2026-82560", source="Snyk Container")
    verdict = review([alert(1, "OTHER", tool="Snyk Container", severity="note")], [entry],
                     today=TODAY, closed=[alert(9, "CVE-2026-82560",
                                                tool="Docker Scout")])

    assert verdict.settled == []
    assert [e.id for e in verdict.unused] == ["CVE-2026-82560"]


def test_a_settled_entry_that_is_also_overdue_still_fails():
    """Both facts hold, and the date is the one that has to be acted on: an entry
    nobody reviewed on time does not get a pass because the scanner went quiet."""
    verdict = review([alert(1, "OTHER", severity="note")],
                     [allowed("CVE-2026-82560", review_by="2026-01-01")],
                     today=TODAY, closed=[alert(9, "CVE-2026-82560")])

    assert not verdict.ok
    assert [e.id for e in verdict.expired] == ["CVE-2026-82560"]


def test_an_open_alert_is_never_settled_by_a_closed_twin():
    """The ordinary case once a finding comes back: open wins, and the entry is
    doing its job."""
    verdict = review([alert(1, "CVE-2026-82560")], [allowed("CVE-2026-82560")],
                     today=TODAY, closed=[alert(9, "CVE-2026-82560")])

    assert verdict.settled == []
    assert verdict.unused == []
    assert verdict.ok


def test_closed_alerts_are_optional():
    """The argument is new; a caller that does not pass it keeps the old
    behaviour, which is what every other test here relies on."""
    verdict = review([alert(1, "OTHER", severity="note")], [allowed("CVE-1")], today=TODAY)

    assert [e.id for e in verdict.unused] == ["CVE-1"]


# ── the file ────────────────────────────────────────────────────────────────

def test_the_file_is_read_with_every_field_required(tmp_path):
    path = tmp_path / "SECURITY-EXCEPTIONS.toml"
    path.write_text(
        '[[exception]]\n'
        'id = "CVE-2026-85091"\n'
        'source = "Docker Scout"\n'
        'where = "zlib, Debian 13 base image"\n'
        'why = "upstream marks it not fixed"\n'
        'review_by = "2026-12-31"\n',
        encoding="utf-8",
    )
    entries = load_exceptions(path)

    assert len(entries) == 1
    assert entries[0].id == "CVE-2026-85091"
    assert entries[0].review_by == "2026-12-31"


@pytest.mark.parametrize("missing", ["id", "where", "why", "review_by"])
def test_an_entry_missing_a_required_field_is_refused(tmp_path, missing):
    """`why` is required because an exception without a reason is a silencer, and
    `review_by` because one without a date never comes back."""
    fields = {"id": "CVE-1", "where": "w", "why": "y", "review_by": "2026-12-31"}
    del fields[missing]
    body = "[[exception]]\n" + "".join(f'{k} = "{v}"\n' for k, v in fields.items())
    path = tmp_path / "x.toml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(ValueError, match=missing):
        load_exceptions(path)


def test_a_malformed_date_is_refused(tmp_path):
    path = tmp_path / "x.toml"
    path.write_text('[[exception]]\nid = "C"\nwhere = "w"\nwhy = "y"\nreview_by = "domani"\n',
                    encoding="utf-8")

    with pytest.raises(ValueError, match="review_by"):
        load_exceptions(path)


def test_a_missing_file_means_no_exceptions_not_an_error(tmp_path):
    """A repository that has never needed one should not have to carry an empty
    file to satisfy the gate."""
    assert load_exceptions(tmp_path / "absent.toml") == []


def test_the_real_file_of_this_repository_parses():
    """Whatever is in it today, it has to be readable and in date — the gate runs
    on it, so a typo here fails every build until someone fixes it."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    entries = load_exceptions(root / "SECURITY-EXCEPTIONS.toml")
    assert entries, "the repository has open findings that need a written reason"
    for entry in entries:
        assert entry.why.strip(), f"{entry.id} has no reason"
        assert dt.date.fromisoformat(entry.review_by) >= TODAY, f"{entry.id} is overdue"


# ── the report ──────────────────────────────────────────────────────────────

def test_the_verdict_explains_itself():
    """Exit codes are read by machines; this text is read by whoever has to act."""
    verdict = review([alert(7, "CVE-NEW")], [allowed("CVE-OLD", review_by="2026-01-01")],
                     today=TODAY)
    text = verdict.describe()

    assert "CVE-NEW" in text
    assert "CVE-OLD" in text
    assert "#7" in text


def test_a_clean_verdict_says_so():
    assert "ok" in Verdict([], [], []).describe().lower()
