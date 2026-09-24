"""Properties, checked against generated input rather than chosen examples.

The DMARC and BIMI tag parsers take a string from DNS — something the domain
owner writes by hand, and gets wrong in ways no fixture anticipates. The email
extractor takes a whole scraped page, where the interesting cases are the
near-misses: example.community, example.com.evil.org.

The `normalize_text` block is the most valuable one here, and the reason is not
the parser: its output is hashed, and that hash is what tells an operator "the
law changed". A normalisation that is not idempotent would report a change in a
text that nobody edited.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from mailradar.checker import _parse_pct, _parse_tags
from mailradar.discover import _extract_emails_from_text
from mailradar.law_fetcher import normalize_text

# ── DMARC / BIMI tag lists ──────────────────────────────────────────────────

_KEY = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=5)
_VALUE = st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126,
                                       blacklist_characters=";"), max_size=20)


@given(st.dictionaries(_KEY, _VALUE, min_size=1, max_size=8))
def test_a_record_built_from_tags_parses_back_to_those_tags(tags):
    """The round trip: what the parser reads is what a domain owner wrote."""
    record = "; ".join(f"{k}={v}" for k, v in tags.items())
    assert _parse_tags(record) == {k: v.strip() for k, v in tags.items()}


@given(_KEY, _VALUE, _VALUE)
def test_a_value_may_contain_an_equals_sign(key, left, right):
    """Documented in the docstring, and true of rua=mailto:a@b?subject=x=y."""
    assert _parse_tags(f"{key}={left}={right}") == {key: f"{left}={right}".strip()}


@given(st.text(max_size=200))
def test_a_fragment_with_no_equals_sign_is_dropped_not_guessed_at(record):
    """Nothing is reported that the record did not contain.

    Stated as two separate facts rather than a round trip, because the parser
    strips both sides: "a =" yields the key "a" with an empty value, so "a="
    never appears in the record verbatim.
    """
    tags = _parse_tags(record)
    assert len(tags) <= record.count("=")
    for key, value in tags.items():
        assert key in record
        assert value in record


@given(st.text(max_size=100))
def test_parsing_a_record_never_raises(record):
    """It is fed whatever the domain's TXT record happens to say."""
    assert isinstance(_parse_tags(record), dict)


# ── DMARC pct ───────────────────────────────────────────────────────────────


@given(st.integers(0, 100))
def test_every_percentage_in_range_is_accepted(pct):
    assert _parse_pct(str(pct)) == pct


@given(st.integers())
def test_a_number_outside_nought_to_a_hundred_is_refused(n):
    """pct=150 is not a stricter policy; it is a malformed record."""
    assert (_parse_pct(str(n)) is None) == (not 0 <= n <= 100)


@given(st.text(max_size=20))
def test_anything_that_is_not_an_integer_is_refused(value):
    """None, never a guess: the value decides how much mail the policy covers."""
    result = _parse_pct(value)
    assert result is None or 0 <= result <= 100


# ── Email addresses scraped off a page ──────────────────────────────────────

_LABEL = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=8)
_LOCAL = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789._%+-", min_size=1, max_size=10)


@given(_LOCAL, _LABEL, st.sampled_from(["com", "it", "org", "co.uk"]))
def test_an_address_on_the_domain_is_found(local, label, tld):
    domain = f"{label}.{tld}"
    assert _extract_emails_from_text(f"write to {local}@{domain} today", domain) == [
        f"{local}@{domain}".lower()
    ]


@given(_LOCAL, _LABEL, _LABEL)
def test_a_longer_domain_that_merely_starts_the_same_is_not_a_match(local, label, extra):
    """example.community is not example.com — the comment above the pattern."""
    domain = f"{label}.com"
    text = f"contact {local}@{domain}{extra}.org for details"
    assert _extract_emails_from_text(text, domain) == []


@given(_LOCAL, _LABEL)
def test_a_subdomain_suffix_attack_is_not_a_match(local, label):
    """example.com.evil.org must not be read as example.com."""
    domain = f"{label}.com"
    text = f"contact {local}@{domain}.evil.org"
    assert _extract_emails_from_text(text, domain) == []


@given(_LOCAL, _LABEL)
def test_a_full_stop_ending_the_sentence_is_not_part_of_the_address(local, label):
    domain = f"{label}.com"
    found = _extract_emails_from_text(f"Write to {local}@{domain}.", domain)
    assert found == [f"{local}@{domain}".lower()]


@given(st.text(max_size=300), _LABEL)
def test_every_address_reported_is_lower_case_and_on_the_domain(text, label):
    domain = f"{label}.com"
    for email in _extract_emails_from_text(text, domain):
        assert email == email.lower()
        assert email.endswith(f"@{domain}")


# ── The hash that decides "the law changed" ─────────────────────────────────

_LEGAL_TEXT = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=0x2FFF, blacklist_categories=("Cs",)),
    max_size=400,
)


@given(_LEGAL_TEXT)
@settings(max_examples=300)
def test_normalising_twice_says_the_same_as_normalising_once(text):
    """If this ever failed, the cache would report a change nobody made."""
    once = normalize_text(text)
    assert normalize_text(once) == once


@given(_LEGAL_TEXT)
def test_the_normal_form_holds_no_run_of_spaces_and_no_edges(text):
    result = normalize_text(text)
    assert "  " not in result
    assert result == result.strip()


@given(_LEGAL_TEXT)
def test_the_normal_form_never_leaves_a_space_before_punctuation(text):
    """"Consiglio ;" is what a removed footnote reference leaves behind."""
    result = normalize_text(text)
    for mark in ";,.:":
        assert f" {mark}" not in result
