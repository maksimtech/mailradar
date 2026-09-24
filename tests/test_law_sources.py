"""
The acts besides the GDPR, on excerpts of the real pages: NIS2 and directive
2019/770 from EUR-Lex, the Italian Consumer Code from Normattiva.
"""
from pathlib import Path

import httpx
import pytest

from mailradar import law_fetcher
from mailradar.law_fetcher import (
    CONSUMER_CODE,
    DIGITAL_CONTENT,
    EPRIVACY,
    GDPR,
    NIS2,
    LawFetchError,
    fetch_provisions,
    parse_articles,
)
from mailradar.law_fetcher import (
    fetch_html as real_fetch_html,
)

FIXTURES = Path(__file__).parent / "fixtures"


def page(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


# ─── acts ─────────────────────────────────────────────────────────────────────

def test_acts():
    assert (NIS2.celex, NIS2.source) == ("32022L2555", "EUR-Lex")
    assert (DIGITAL_CONTENT.celex, DIGITAL_CONTENT.source) == ("32019L0770", "EUR-Lex")
    # Not on EUR-Lex: Normattiva, by its NIR URN
    assert CONSUMER_CODE.celex == "urn:nir:stato:decreto.legislativo:2005-09-06;206"
    assert CONSUMER_CODE.source == "Normattiva"
    assert CONSUMER_CODE.id_label == "URN"
    assert GDPR.id_label == EPRIVACY.id_label == "CELEX"


def test_acts_have_distinct_names_and_ids():
    acts = (GDPR, EPRIVACY, NIS2, DIGITAL_CONTENT, CONSUMER_CODE)
    assert len({a.name for a in acts}) == len({a.celex for a in acts}) == len(acts)


# ─── NIS2 (EUR-Lex, Official Journal layout) ─────────────────────────────────

def test_nis2_article_21():
    texts = parse_articles(page("nis2_it_excerpt.html"), ("21",))
    assert {"21", "21(1)", "21(2)", "21(2)(a)", "21(2)(j)", "21(5)"} <= set(texts)
    assert texts["21(1)"].startswith(
        "1. Gli Stati membri provvedono affinché i soggetti essenziali e importanti adottino misure"
    )
    assert texts["21(2)(e)"] == (
        "e) sicurezza dell'acquisizione, dello sviluppo e della manutenzione dei sistemi "
        "informatici e di rete, compresa la gestione e la divulgazione delle vulnerabilità;"
    )
    assert not any(ref.startswith("22") for ref in texts)


# ─── Directive 2019/770 ──────────────────────────────────────────────────────

def test_digital_content_articles():
    texts = parse_articles(page("dir2019_770_it_excerpt.html"), ("3", "7", "8"))
    assert texts["3(8)"].startswith(
        "8. Il diritto dell’Unione in materia di protezione dei dati personali si applica a "
        "qualsiasi dato personale trattato in relazione ai contratti di cui al paragrafo 1."
    )
    assert texts["8(1)(b)"].startswith("b) è della quantità e presenta la qualità e le caratteristiche")
    # Its own sub-points i) to iii) are part of the point
    assert "iii) la decisione di acquistare" in texts["8(1)(b)"]
    # Article 7 has lettered points and no numbered paragraph
    assert texts["7(a)"].startswith("a) corrisponde alla descrizione")


# ─── Consumer Code (Normattiva) ──────────────────────────────────────────────

def test_normattiva_article_20():
    texts = parse_articles(page("normattiva_cdc_art20.html"), ("20",))
    assert sorted(texts) == ["20", "20(1)", "20(2)", "20(3)", "20(4)", "20(4)(a)", "20(4)(b)", "20(5)"]
    assert texts["20(1)"] == "1. Le pratiche commerciali scorrette sono vietate."
    assert texts["20(4)(b)"] == "b) aggressive di cui agli articoli 24, 25 e 26."
    assert texts["20"].split("\n") == [texts[f"20({n})"] for n in range(1, 6)]


def test_normattiva_update_marks_and_heading_are_dropped():
    # Normattiva shows amended text between (( and ))
    texts = parse_articles(page("normattiva_cdc_art20.html"), ("20",))
    for text in texts.values():
        assert "((" not in text and "))" not in text
        assert "Divieto delle pratiche commerciali scorrette" not in text
        assert "Art. 20" not in text
        assert "vigore" not in text


def test_normattiva_articles_21_and_49():
    assert parse_articles(page("normattiva_cdc_art21.html"), ("21",))["21(1)(a)"] == (
        "a) l'esistenza o la natura del prodotto;"
    )
    assert parse_articles(page("normattiva_cdc_art49.html"), ("49",))["49(1)(a)"] == (
        "a) le caratteristiche principali dei beni o servizi, nella misura adeguata al "
        "supporto e ai beni o servizi;"
    )


def test_normattiva_page_of_another_article_raises():
    # Normattiva answers 200 for an article that does not exist
    with pytest.raises(LawFetchError, match="49"):
        parse_articles(page("normattiva_cdc_art20.html"), ("49",))


def test_fetch_consumer_code_one_page_per_article(monkeypatch):
    urls = []

    def fake_fetch_html(url, **kwargs):
        urls.append(url)
        return page(f"normattiva_cdc_art{url.split('~art')[1].split('!')[0]}.html")

    monkeypatch.setattr(law_fetcher, "fetch_html", fake_fetch_html)
    provisions = fetch_provisions(CONSUMER_CODE, ("20", "21"))

    assert urls == [
        "https://www.normattiva.it/uri-res/N2Ls?urn:nir:stato:decreto.legislativo:2005-09-06;206~art20!vig=",
        "https://www.normattiva.it/uri-res/N2Ls?urn:nir:stato:decreto.legislativo:2005-09-06;206~art21!vig=",
    ]
    assert provisions["20(1)"].celex == CONSUMER_CODE.celex
    assert provisions["21(1)(a)"].key == (CONSUMER_CODE.celex, "21(1)(a)")


def test_fetch_eurlex_acts_by_celex(monkeypatch):
    urls = []

    def fake_fetch_html(url, **kwargs):
        urls.append(url)
        return page("nis2_it_excerpt.html" if "2555" in url else "dir2019_770_it_excerpt.html")

    monkeypatch.setattr(law_fetcher, "fetch_html", fake_fetch_html)
    fetch_provisions(NIS2, ("21",))
    fetch_provisions(DIGITAL_CONTENT, ("3", "8"))

    assert urls == [
        "https://publications.europa.eu/resource/celex/32022L2555",
        "https://publications.europa.eu/resource/celex/32019L0770",
    ]


def test_errors_name_the_source():
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(503)))
    with pytest.raises(LawFetchError, match="Normattiva answered HTTP 503"):
        real_fetch_html("https://www.normattiva.it/uri-res/N2Ls?x", client=client)
    with pytest.raises(LawFetchError, match="EUR-Lex answered HTTP 503"):
        real_fetch_html("https://eur-lex.europa.eu/x", client=client)
