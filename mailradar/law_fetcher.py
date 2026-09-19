"""
MailRadar — EU and Italian law text from EUR-Lex and Normattiva.

Downloads the acts MailRadar reports cite and extracts their articles, down to
paragraph and point: "5", "5(1)", "5(1)(a)". EU acts come from EUR-Lex (the
GDPR, the consolidated ePrivacy directive, NIS2, directive 2019/770), the
Italian Consumer Code from Normattiva, the official source of Italian law in
force. Each provision carries the SHA-256 of its
text, so a report can state exactly which wording of the law it applied.

The hash is computed on the UTF-8 text stored with it: whitespace collapsed to
single spaces, footnote references and amendment markers removed, paragraphs
of an article one per line. Anyone can recompute it from the text in
~/.mailradar/law_cache.json.

Shared by the Radar tools; the first version, in APKRadar, read the GDPR only.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Iterator, Optional, Union

import httpx

from mailradar import __version__

SOURCE_URL = "https://eur-lex.europa.eu/legal-content/{lang}/TXT/HTML/?uri=CELEX:{celex}"
# One page per article, in the version in force (!vig=)
NORMATTIVA_URL = "https://www.normattiva.it/uri-res/N2Ls?{urn}~art{article}!vig="
USER_AGENT = f"MailRadar/{__version__} (+https://github.com/maksimtech/mailradar)"


@dataclass(frozen=True)
class Act:
    name: str    # as cited in reports: "GDPR"
    celex: str   # EUR-Lex document number, or the NIR URN of an Italian act
    note: str = ""
    source: str = "EUR-Lex"   # or "Normattiva"

    @property
    def id_label(self) -> str:
        return "CELEX" if self.source == "EUR-Lex" else "URN"


GDPR = Act("GDPR", "32016R0679")
# The consolidated text: art. 5(3) as amended by directive 2009/136/EC, which
# requires prior consent. The 2002 original (32002L0058) only required the
# right to refuse.
EPRIVACY = Act(
    "ePrivacy dir. 2002/58/CE",
    "02002L0058-20091219",
    "testo consolidato al 19.12.2009",
)
NIS2 = Act("NIS2 dir. 2022/2555", "32022L2555")
DIGITAL_CONTENT = Act("Contenuti digitali dir. 2019/770", "32019L0770")
# Not on EUR-Lex, which lists Italian transposition measures without their text
CONSUMER_CODE = Act(
    "Codice del Consumo D.Lgs. 206/2005",
    "urn:nir:stato:decreto.legislativo:2005-09-06;206",
    "testo vigente",
    source="Normattiva",
)


class LawFetchError(Exception):
    """The source could not be reached, or its page did not contain the articles."""


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def utc_stamp(moment: datetime) -> str:
    """ISO 8601 UTC timestamp, e.g. 2026-09-19T14:00:00Z."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Provision:
    article: str       # "5(1)(a)"
    text: str
    sha256: str
    fetched_at: str    # when this wording was downloaded, ISO 8601 UTC
    celex: str

    @classmethod
    def from_text(cls, article: str, text: str, fetched_at: str, celex: str) -> "Provision":
        return cls(
            article=article, text=text, sha256=text_sha256(text),
            fetched_at=fetched_at, celex=celex,
        )

    @classmethod
    def from_dict(cls, data: dict) -> "Provision":
        values = {key: data[key] for key in ("article", "text", "sha256", "fetched_at", "celex")}
        if not all(isinstance(value, str) for value in values.values()):
            raise TypeError("provision fields must be strings")
        return cls(**values)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def key(self) -> tuple[str, str]:
        """Article numbers repeat across acts: 5(3) is in both the GDPR and ePrivacy."""
        return self.celex, self.article


# ─── HTML → tree ──────────────────────────────────────────────────────────────

_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"}
_BLOCK = {"p", "div", "table", "tbody", "thead", "tr", "td", "th", "li", "ul", "ol", "br"}


class _Element:
    __slots__ = ("tag", "attrs", "children")

    def __init__(self, tag: str, attrs: dict):
        self.tag = tag
        self.attrs = attrs
        self.children: list[Union[_Element, str]] = []

    @property
    def classes(self) -> list[str]:
        return (self.attrs.get("class") or "").split()


class _TreeBuilder(HTMLParser):
    """Minimal DOM. Drops scripts, styles, footnote references and the
    ▼B / ▼M2 amendment markers of consolidated texts."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _Element("#root", {})
        self._stack = [self.root]
        self._skipping = 0

    @staticmethod
    def _skip(tag: str, attrs: dict) -> bool:
        classes = (attrs.get("class") or "").split()
        return (
            tag in ("script", "style")
            # <a href="#ntr19-...">(19)</a>
            or (tag == "a" and (attrs.get("href") or "").startswith("#ntr"))
            # <p class="modref"><a>▼M2</a></p>
            or "modref" in classes
        )

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if self._skipping:
            if tag not in _VOID:
                self._skipping += 1
            return
        if self._skip(tag, attrs):
            if tag not in _VOID:
                self._skipping = 1
            return
        element = _Element(tag, attrs)
        self._stack[-1].children.append(element)
        if tag not in _VOID:
            self._stack.append(element)

    def handle_startendtag(self, tag, attrs):
        if not self._skipping:
            self._stack[-1].children.append(_Element(tag, dict(attrs)))

    def handle_endtag(self, tag):
        if self._skipping:
            if tag not in _VOID:
                self._skipping -= 1
            return
        for i in range(len(self._stack) - 1, 0, -1):
            if self._stack[i].tag == tag:
                del self._stack[i:]
                return

    def handle_data(self, data):
        if not self._skipping:
            self._stack[-1].children.append(data)


def _elements(node: _Element) -> Iterator[_Element]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed([c for c in current.children if isinstance(c, _Element)]))


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFC", text)
    text = re.sub(r"\s+", " ", text)
    # Removing a footnote reference leaves "Consiglio ;"
    text = re.sub(r" (?=[;,.:])", "", text)
    return text.strip()


def _raw_text(node: Union[_Element, str]) -> str:
    if isinstance(node, str):
        return node
    inner = "".join(_raw_text(child) for child in node.children)
    return f" {inner} " if node.tag in _BLOCK else inner


def _text(node: Union[_Element, str]) -> str:
    return normalize_text(_raw_text(node))


# ─── Tree → provisions ────────────────────────────────────────────────────────

_PARAGRAPH_ID = re.compile(r"^\d{3}\.\d{3}$")   # <div id="005.001"> is art. 5(1)
_PARAGRAPH = re.compile(r"^(\d+)\. ")           # "1. I dati personali sono:"
_NUMBERED = re.compile(r"^(\d+)\) ")            # GDPR art. 4: "1) «dato personale»: ..."
_LETTER = re.compile(r"^([a-z]{1,4})\)$")       # table label cell: "a)"
_POINT = re.compile(r"^([a-z]{1,4})\) ")          # Normattiva point: "a) ingannevoli ..."


def _is_heading(node: _Element) -> bool:
    return any(
        c in ("oj-ti-art", "eli-title", "title-article-norm", "stitle-article-norm")
        for c in node.classes
    )


def _flatten(nodes: list) -> Iterator[Union[_Element, str]]:
    """Paragraph content as a sequence of <p>, <table> and loose text."""
    for node in nodes:
        if isinstance(node, str):
            if node.strip():
                yield node
        elif _is_heading(node):
            continue
        elif node.tag in ("div", "tbody") and not _PARAGRAPH_ID.match(node.attrs.get("id", "")):
            yield from _flatten(node.children)
        else:
            yield node


def _table_point(table: _Element) -> Optional[tuple[str, str]]:
    """(letter, text) of a point laid out as a label cell and a text cell."""
    rows = [
        row
        for child in table.children if isinstance(child, _Element)
        for row in ([child] if child.tag == "tr" else child.children if child.tag == "tbody" else [])
        if isinstance(row, _Element) and row.tag == "tr"
    ]
    if len(rows) != 1:
        return None
    # Direct cells only: a nested table inside the text cell is part of its text
    cells = [c for c in rows[0].children if isinstance(c, _Element) and c.tag == "td"]
    if len(cells) < 2:
        return None
    label = _text(cells[0])
    match = _LETTER.match(label)
    if not match:
        return None
    content = " ".join(_text(cell) for cell in cells[1:])
    return match.group(1), normalize_text(f"{label} {content}")


def _parse_block(nodes: list, prefix: str) -> tuple[list[str], dict[str, str]]:
    """
    Split paragraph content into lines and cite-able points.

    Lettered points are tables, "a)" | "text". Numbered points (the
    definitions of GDPR art. 4) are paragraphs starting with "1)"; their own
    lettered sub-points stay part of them.
    """
    items: list[tuple[Optional[str], list[str]]] = []
    numbered = False
    for node in _flatten(nodes):
        point = _table_point(node) if isinstance(node, _Element) and node.tag == "table" else None
        if point is not None:
            letter, text = point
            if numbered:
                items[-1][1].append(text)
            else:
                items.append((f"{prefix}({letter})", [text]))
            continue
        text = _text(node)
        if not text:
            continue
        match = _NUMBERED.match(text)
        numbered = bool(match)
        items.append((f"{prefix}({match.group(1)})" if match else None, [text]))

    lines = [" ".join(parts) for _, parts in items]
    points = {ref: " ".join(parts) for ref, parts in items if ref}
    return lines, points


def _parse_paragraphs(groups: list[tuple[int, list]], number: str) -> dict[str, str]:
    texts: dict[str, str] = {}
    lines = []
    for paragraph, nodes in groups:
        ref = f"{number}({paragraph})"
        paragraph_lines, points = _parse_block(nodes, ref)
        texts[ref] = " ".join(paragraph_lines)
        texts.update(points)
        lines.append(texts[ref])
    texts[number] = "\n".join(lines)
    return texts


def _parse_eli_article(article: _Element, number: str) -> dict[str, str]:
    """Official Journal layout: <div id="art_5"> with a <div id="005.001"> per paragraph."""
    paragraphs = [
        e for e in _elements(article)
        if e.tag == "div" and _PARAGRAPH_ID.match(e.attrs.get("id", ""))
    ]
    if paragraphs:
        return _parse_paragraphs(
            [(int(div.attrs["id"].split(".")[1]), div.children) for div in paragraphs], number
        )
    lines, points = _parse_block(article.children, number)
    return {**points, number: "\n".join(lines)}


def _without_update_marks(text: str) -> str:
    """Normattiva wraps amended text in (( and )): not part of the law."""
    return normalize_text(text.replace("((", " ").replace("))", " "))


def _parse_normattiva_article(root: _Element, number: str) -> dict[str, str]:
    """
    Normattiva layout (Akoma Ntoso): <h2 class="article-num-akn" id="art_20">
    in a <div class="bodyTesto">, a <div class="art-comma-div-akn"> per
    paragraph ("comma") with its number in <span class="comma-num-akn">, and
    lettered points in <div class="pointedList-rest-akn">.
    """
    for body in _elements(root):
        if "bodyTesto" not in body.classes or not any(
            "article-num-akn" in e.classes and e.attrs.get("id") == f"art_{number}"
            for e in _elements(body)
        ):
            continue
        groups: list[tuple[Optional[int], str, dict[str, str]]] = []
        for comma in (e for e in _elements(body) if "art-comma-div-akn" in e.classes):
            text = _without_update_marks(_text(comma))
            if not text:
                continue
            num = next((e for e in _elements(comma) if "comma-num-akn" in e.classes), None)
            match = _PARAGRAPH.match(_text(num) + " ") if num is not None else None
            paragraph = int(match.group(1)) if match else None
            points = {}
            for item in (e for e in _elements(comma) if "pointedList-rest-akn" in e.classes):
                point = _without_update_marks(_text(item))
                letter = _POINT.match(point)
                if letter and paragraph is not None:
                    points[f"{number}({paragraph})({letter.group(1)})"] = point
            groups.append((paragraph, text, points))

        texts: dict[str, str] = {}
        for paragraph, text, points in groups:
            if paragraph is not None:
                texts[f"{number}({paragraph})"] = text
            texts.update(points)
        texts[number] = "\n".join(text for _, text, _ in groups)
        return texts
    return {}


def _ends_article(node: _Element) -> bool:
    return any(
        c == "title-article-norm" or c.startswith(("hd-", "title-doc", "toc-")) or c == "footnote"
        for c in node.classes
    )


def _parse_consolidated_article(root: _Element, number: str) -> dict[str, str]:
    """
    Consolidated layout: a flat run of <p class="norm"> after
    <p class="title-article-norm">Articolo 5</p>, up to the next article.
    Paragraphs are recognised by their "1. " prefix.
    """
    for parent in _elements(root):
        children = parent.children
        for i, node in enumerate(children):
            if (
                isinstance(node, _Element)
                and "title-article-norm" in node.classes
                and _text(node) == f"Articolo {number}"
            ):
                body = []
                for sibling in children[i + 1:]:
                    if isinstance(sibling, _Element) and _ends_article(sibling):
                        break
                    body.append(sibling)
                return _split_flat_paragraphs(body, number)
    return {}


def _split_flat_paragraphs(body: list, number: str) -> dict[str, str]:
    groups: list[tuple[int, list]] = []
    intro: list = []
    for node in _flatten(body):
        match = _PARAGRAPH.match(_text(node)) if isinstance(node, _Element) and node.tag == "p" else None
        if match:
            groups.append((int(match.group(1)), [node]))
        elif groups:
            groups[-1][1].append(node)
        else:
            intro.append(node)
    if not groups:
        lines, points = _parse_block(intro, number)
        return {**points, number: "\n".join(lines)}
    if intro:
        groups[0][1][:0] = intro
    return _parse_paragraphs(groups, number)


def parse_articles(html: str, articles: tuple[str, ...]) -> dict[str, str]:
    """
    Extract articles from an EUR-Lex page (Official Journal or consolidated
    layout) or a Normattiva article page.

    Returns:
        Text by reference, for each article and each of its paragraphs and
        points: {"5": ..., "5(1)": ..., "5(1)(a)": ...}.

    Raises:
        LawFetchError: an article is missing, e.g. the page is not the act.
    """
    builder = _TreeBuilder()
    builder.feed(html)
    builder.close()
    by_id = {e.attrs["id"]: e for e in _elements(builder.root) if e.tag == "div" and "id" in e.attrs}

    texts: dict[str, str] = {}
    for number in articles:
        article = by_id.get(f"art_{number}")
        if article is not None:
            parsed = _parse_eli_article(article, number)
        else:
            parsed = (
                _parse_normattiva_article(builder.root, number)
                or _parse_consolidated_article(builder.root, number)
            )
        if not parsed.get(number):
            raise LawFetchError(f"Article {number} not found in the EUR-Lex page")
        texts.update(parsed)
    return texts


# ─── Download ─────────────────────────────────────────────────────────────────

def fetch_html(url: str, *, client: Optional[httpx.Client] = None, timeout: float = 30.0) -> str:
    """Download a page. Anything but HTTP 200 is an error: EUR-Lex answers
    some automated requests with 202 and a JavaScript challenge."""
    source = "Normattiva" if "normattiva.it" in url else "EUR-Lex"
    headers = {"User-Agent": USER_AGENT}
    try:
        if client is None:
            with httpx.Client(timeout=timeout, follow_redirects=True) as own_client:
                response = own_client.get(url, headers=headers)
        else:
            response = client.get(url, headers=headers)
    except httpx.HTTPError as e:
        raise LawFetchError(f"{source} unreachable: {e}") from e
    if response.status_code != 200:
        raise LawFetchError(f"{source} answered HTTP {response.status_code}")
    return response.text


def fetch_provisions(
    act: Act,
    articles: tuple[str, ...],
    *,
    lang: str = "IT",
    now: Optional[datetime] = None,
    client: Optional[httpx.Client] = None,
) -> dict[str, Provision]:
    """Download `act` and return the provisions of `articles`, by reference."""
    if act.source == "Normattiva":
        texts: dict[str, str] = {}
        for article in articles:
            html = fetch_html(NORMATTIVA_URL.format(urn=act.celex, article=article), client=client)
            texts.update(parse_articles(html, (article,)))
    else:
        html = fetch_html(SOURCE_URL.format(lang=lang, celex=act.celex), client=client)
        texts = parse_articles(html, articles)
    fetched_at = utc_stamp(now or datetime.now(timezone.utc))
    return {
        ref: Provision.from_text(ref, text, fetched_at, act.celex)
        for ref, text in texts.items()
    }
