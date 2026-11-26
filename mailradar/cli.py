"""
MailRadar — CLI interface.
"""

import contextlib
import re
import sys
from typing import Any, cast
from urllib.parse import urlsplit

import typer
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typer.core import TyperGroup

import mailradar
from mailradar.checker import DomainReport, analyze_domain, dkim_unusable
from mailradar.reporter import visible


def enable_utf8_output() -> None:
    """Make stdout and stderr accept characters the console cannot encode.

    On Windows the console code page is cp1252, and Python encodes output with
    it: the first emoji — the one in this CLI's own help text — ended the
    program with UnicodeEncodeError before any command had run. It was never
    the command failing, only the printing of its output.

    errors="replace" rather than "strict": a glyph the terminal cannot show
    should come out as a question mark, never as a traceback.

    Streams that cannot be reconfigured are left alone. pytest's capture and
    anything wrapping a pipe are not TextIOWrapper, and replacing them would
    break whatever is reading them; a cosmetic setting is not worth raising
    over, so this gives up quietly.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if encoding == "utf8":
            continue
        with contextlib.suppress(ValueError, OSError):
            reconfigure(encoding="utf-8", errors="replace")

enable_utf8_output()


# sysexits.h EX_USAGE. Click exits 2 on a usage error, and 2 is `check`'s grade
# CRITICAL: a script could not tell a wrong command line from a critical domain.
EX_USAGE = 64

# Click's UsageError, the class of every command-line error. Typer ships its
# own copy of Click and exports BadParameter, whose base it is, but not it.
_UsageError = cast(type[Exception], typer.BadParameter.__bases__[0])


@contextlib.contextmanager
def _usage_exit_code():
    try:
        yield
    except _UsageError as e:
        e.exit_code = EX_USAGE
        raise


class _Commands(TyperGroup):
    """The app's group: every usage error, at any level, exits EX_USAGE.

    make_context parses the group's own command line; invoke resolves the
    command and parses its arguments and options, callbacks included.
    """

    def make_context(self, *args: Any, **kwargs: Any) -> Any:
        with _usage_exit_code():
            return super().make_context(*args, **kwargs)

    def invoke(self, ctx: Any) -> Any:
        with _usage_exit_code():
            return super().invoke(ctx)


app = typer.Typer(
    name="mailradar",
    help="📡 Email security posture analyzer — DMARC, SPF, DKIM, BIMI, VMC & GPG audit tool",
    add_completion=False,
    cls=_Commands,
)

# emoji=False: Rich reads `:name:` as an emoji shortcode wherever it prints a
# string, markup or not, and SPF's `ip6:2001:db8:100::/48` came out as
# `2001:db8💯:/48`. The emoji this CLI prints are written as characters.
console = Console(emoji=False)


def _s(value: object) -> str:
    """Outside data (DNS, keyservers, HTTP, the user's own input) made safe to put in Rich markup.

    _s() neutralises `[tag]` only, and Rich drops just BEL, BS, VT, FF and
    CR: an ESC in a TXT record reached the terminal as a command. Control
    characters are written out first, then the markup is escaped.
    """
    return escape(visible(str(value)))


@contextlib.contextmanager
def _status(message: str):
    """console.status(), flushing the streams before the spinner stops.

    While the spinner runs, Rich replaces sys.stdout and sys.stderr with a
    FileProxy that holds text until it meets a newline, and `Live` puts the
    original streams back without flushing it. A partial line written by a library
    stays in that buffer and is printed only when the interpreter finalises the
    proxy, at a point where importing is no longer possible:

        Exception ignored while finalizing file <rich.file_proxy.FileProxy ...>
        ImportError: sys.meta_path is None, Python is likely shutting down

    A successful command therefore ends in a traceback, and whoever is watching
    has no way of knowing the result was valid. Only on a terminal: through a pipe
    Rich does not install the proxy and the defect cannot be seen. Observed on
    APKRadar with rich 15.0.0 and Python 3.14.7; here the spinners wrap the DNS
    queries and the sending.

    The `finally` also covers the case with an exception: that is the one where
    the library's partial message matters most.
    """
    # Both flushes in a `finally`, including the outer one. It sat after the
    # `with` block until 2026-09-29, where an exception leaving the body skipped
    # it — the path where a library's partial line matters most, because it is the
    # run about to print a traceback. SonarCloud's python:S9152 found it; no test
    # did, because every test exercised the success path.
    try:
        with console.status(message):
            try:
                yield
            finally:
                sys.stdout.flush()
                sys.stderr.flush()
    finally:
        console.file.flush()



def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"MailRadar {mailradar.__version__}")
        raise typer.Exit(0)


@app.callback()
def _root(
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit",
    ),
) -> None:
    """📡 Email security posture analyzer — DMARC, SPF, DKIM, BIMI, VMC & GPG audit tool"""


def _score_color(score: int | None) -> str:
    if score is None:
        return "yellow"
    if score >= 90:
        return "bright_green"
    elif score >= 75:
        return "green"
    elif score >= 50:
        return "yellow"
    elif score >= 25:
        return "orange3"
    else:
        return "red"


def _grade_emoji(grade: str) -> str:
    return {
        "EXCELLENT": "🟢",
        "GOOD": "🟢",
        "MODERATE": "🟡",
        "POOR": "🟠",
        "CRITICAL": "🔴",
    }.get(grade, "⚪")


def _bool_icon(value: bool) -> str:
    return "✅" if value else "❌"


# A check whose DNS lookup failed is neither configured nor missing
_UNVERIFIED = "[yellow]Not verified: DNS lookup failed[/yellow]"
# The local resolver returned no records and nothing could be compared (#150).
# Each label says exactly what is known and stands on its own: a private
# resolver alone is the common case, not a cause, and outside the terminal
# there is no warning "above" to point at.
_NO_COMPARISON = ("[yellow]Not verified: the local resolver returned no records, "
                  "and no public resolver could be reached to compare[/yellow]")


def _internal_view(report: DomainReport) -> str:
    """The label of a check an internal view left empty, shown by the public resolver (#150)."""
    from mailradar.checker import PUBLIC_RESOLVER

    seen = report.public_records
    verb = "is" if len(seen) == 1 else "are"
    return (f"[yellow]Not graded: the local resolver shows an internal view "
            f"({_s(' and '.join(seen))} {verb} visible through {PUBLIC_RESOLVER})[/yellow]")

# The Details column
_DETAILS_WIDTH = 55


def _fit(text: str, width: int = _DETAILS_WIDTH) -> str:
    """`text` cut to `width` with an ellipsis, so a cut is visible: 'include:spf.protection.outlo' was not."""
    return text if len(text) <= width else text[:width - 1] + "…"


def _check_score_cell(check: str, result: Any) -> Text:
    """The Score cell of one check: its points, coloured by the share of MAX_SCORES[check] they are.

    Coloured on the 0-100 scale of the total, a perfect SPF (20 of 20) came
    out red. A check that was not verified has no points to show: it said 0.
    """
    from mailradar.checker import MAX_SCORES

    if result.error:
        return Text("—", style="yellow")
    return Text(str(result.score), style=_score_color(round(result.score * 100 / MAX_SCORES[check])))


def _unverified(report: DomainReport) -> list[str]:
    """The DNS lookups that failed, i.e. what the report cannot vouch for."""
    checks = (report.dmarc, report.spf, report.dkim, report.bimi, report.mta_sts, report.tls_rpt)
    return [check.error for check in checks if check.error]


def _print_report(report: DomainReport) -> None:
    color = _score_color(report.total_score)
    emoji = _grade_emoji(report.grade)
    # Answered by an internal view is not the same as unanswered (#150)
    if report.public_records:
        unverified = _internal_view(report)
    elif report.split_horizon:
        unverified = _NO_COMPARISON
    else:
        unverified = _UNVERIFIED

    if report.public_records:
        # Shown, not guessed: nothing was left unanswered, the view is another
        score = f"[{color}]N/A — not graded: the local resolver shows an internal view[/{color}]"
    elif report.total_score is None:
        # No number: every check a lookup did not answer would have counted 0
        score = (f"[{color}]N/A — analysis incomplete, not verified: "
                 f"{_s(', '.join(report.unverified))}[/{color}]")
    else:
        score = f"[{color}]{report.total_score}/100 — {emoji} {report.grade}[/{color}]"
    console.print()
    console.print(Panel(
        f"[bold]Domain:[/bold] {_s(report.domain)}\n"
        f"[bold]Score:[/bold] {score}",
        title="📡 MailRadar Report",
        border_style=color,
    ))
    if report.split_horizon:
        console.print(f"[yellow]⚠️  {_s(report.split_horizon)}[/yellow]")
    if report.public_view:
        console.print(f"[dim]{_s(report.public_view)}[/dim]")

    # DMARC
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Check", style="bold", width=12)
    table.add_column("Status", width=6)
    table.add_column("Details", width=_DETAILS_WIDTH)
    table.add_column("Score", width=8, justify="right")

    # DMARC row
    d = report.dmarc
    dmarc_detail = ""
    if d.present:
        dmarc_detail = (
            f"p={_s(d.policy)} | pct={d.pct} | "
            f"adkim={'s' if d.adkim == 's' else 'r'} | "
            f"aspf={'s' if d.aspf == 's' else 'r'} | "
            f"rua={'✓' if d.rua else '✗'} | ruf={'✓' if d.ruf else '✗'}"
        )
        if d.inherited:
            # Record trovato su un dominio padre (RFC 7489 §6.6.3)
            dmarc_detail += f" | [yellow]via {_s(d.found_at)}[/yellow]"
    elif d.error:
        dmarc_detail = unverified
    else:
        dmarc_detail = "[red]Not configured[/red]"

    dmarc_icon = "✅" if d.policy == "reject" else ("⚠️ " if d.present or d.error else "❌")
    table.add_row("DMARC", dmarc_icon, dmarc_detail, _check_score_cell("dmarc", d))

    # SPF row
    s = report.spf
    spf_detail = (escape(_fit(visible(s.raw))) if s.present
                  else (unverified if s.error else "[red]Not configured[/red]"))
    spf_ok = s.present and not s.permissive and not s.permerror
    spf_icon = "✅" if spf_ok else ("⚠️ " if s.present or s.error else "❌")
    table.add_row("SPF", spf_icon, spf_detail, _check_score_cell("spf", s))

    # DKIM row
    k = report.dkim
    dkim_detail = ""
    if k.present and len(k.keys) > 1:
        # Every active key, the weakest first: it is the one the score measures
        dkim_detail = " | ".join(f"{_s(selector)}: {_s(key)}" for selector, key in k.keys.items())
    elif k.present:
        # The checker's own description: a malformed key, or one only in
        # testing mode, is not "0-bit RSA" or a plain "2048-bit RSA"
        key = k.keys.get(k.selector) or ("Ed25519" if k.key_type == "ed25519" else f"{k.key_bits}-bit RSA")
        dkim_detail = f"selector: {_s(k.selector)} | {_s(key)}"
    elif k.error:
        dkim_detail = unverified
    elif k.selector:
        # Found, but revoked (empty p=): there is no key to sign with
        dkim_detail = f"[red]selector: {_s(k.selector)} | key revoked[/red]"
    elif k.tried:
        # A selector is the sender's choice: not found is not absent
        dkim_detail = f"[red]Not found under {k.tried} common selectors[/red]"
    else:
        dkim_detail = "[red]Not found (tried common selectors)[/red]"
    # A key nothing can be verified with, or one only in testing mode: published,
    # and still no signature a receiver counts
    dkim_icon = ("❌" if dkim_unusable(k) else "✅") if k.present else ("⚠️ " if k.error else "❌")
    table.add_row("DKIM", dkim_icon, dkim_detail, _check_score_cell("dkim", k))

    # BIMI row
    b = report.bimi
    bimi_detail = ""
    if b.present:
        bimi_detail = f"SVG: {'✓' if b.svg_valid else '✗'} | VMC: {'✓' if b.vmc_present else '✗'}"
    elif b.error:
        bimi_detail = unverified
    else:
        bimi_detail = "[dim]Not configured[/dim]"
    bimi_icon = "✅" if (b.present and b.vmc_present) else ("⚠️ " if b.present or b.error else "❌")
    table.add_row("BIMI/VMC", bimi_icon, bimi_detail, _check_score_cell("bimi", b))

    # MTA-STS row
    m = report.mta_sts
    mts_detail = f"mode: {_s(m.mode)}" if m.present else (unverified if m.error else "[dim]Not configured[/dim]")
    mts_icon = "✅" if (m.present and m.mode == "enforce") else ("⚠️ " if m.present or m.error else "❌")
    table.add_row("MTA-STS", mts_icon, mts_detail, _check_score_cell("mta_sts", m))

    # TLS-RPT row
    t = report.tls_rpt
    tls_detail = (
        f"rua: {escape(_fit(visible(t.rua), _DETAILS_WIDTH - len('rua: ')))}" if t.present
        else (unverified if t.error else "[dim]Not configured[/dim]")
    )
    tls_icon = "✅" if t.present else ("⚠️ " if t.error else "❌")
    table.add_row("TLS-RPT", tls_icon, tls_detail, _check_score_cell("tls_rpt", t))

    # GPG row
    g = report.gpg
    keyserver = _s(urlsplit(g.keyserver or "").hostname or g.keyserver or "")
    if g.found and g.verified:
        gpg_detail = f"uid: {_s(g.uid)} | {keyserver}"
        gpg_icon = "✅"
    elif g.found:
        # Anyone can upload a key under any address on this keyserver
        gpg_detail = f"uid: {_s(g.uid)} | {keyserver} [yellow]— address not verified[/yellow]"
        gpg_icon = "⚠️ "
    elif g.error:
        gpg_detail = "[yellow]Not verified: keyserver did not answer[/yellow]"
        gpg_icon = "⚠️ "
    else:
        gpg_detail = "[dim]No public key on keyservers[/dim]"
        gpg_icon = "❌"
    table.add_row("GPG", gpg_icon, gpg_detail, _check_score_cell("gpg", g))

    console.print(table)

    # Issues
    all_issues = (
        report.dmarc.issues +
        report.spf.issues +
        report.dkim.issues +
        report.bimi.issues +
        report.mta_sts.issues +
        report.tls_rpt.issues +
        report.gpg.issues +
        report.mx.issues
    )

    if all_issues:
        console.print()
        console.print("[bold yellow]⚠️  Issues found:[/bold yellow]")
        for issue in all_issues:
            console.print(f"  [dim]•[/dim] {_s(issue)}")

    # Findings that are not problems and cost no points: a range written from
    # an inner address, a range an include already holds, 10 lookups of 10,
    # a domain that sends mail with no MX
    notes = report.spf.notes + report.mx.notes
    if notes:
        console.print()
        console.print("[bold cyan]ℹ️  Notes (informational, no points lost):[/bold cyan]")
        for note in notes:
            console.print(f"  [dim]·[/dim] {_s(note)}")

    console.print()



def _law_check(subject, out=None, **context):
    """Run the law check; any failure is reported and never fails the command."""
    from mailradar import law_checker

    try:
        return law_checker.check(subject, **context)
    except Exception as e:
        (out or console).print(f"[yellow]⚠️  Law check failed: {_s(str(e))}[/yellow]\n")
        return None


def _print_law_check(law, out=None) -> None:
    """Cite the provisions applied to the findings, with their SHA-256."""
    from mailradar.law_checker import FINDING_TITLES, format_citation

    out = out or console
    if law is None or not (law.citations or law.notes):
        return

    if law.citations:
        # Not over a note alone: the GPG suggestion cites nothing
        out.print("[bold]⚖️  Provisions applied[/bold]")
    for status in law.acts:
        act = status.act
        name = _s(act.name)
        # Which source was tried, and whether it was unreachable or answered
        # without the text cited: "EUR-Lex unreachable" whatever happened was
        # how a reached page with a moved point used to be reported
        reason = _s(status.reason or "")
        if status.source == "verified":
            origin = _s(status.origin or act.source)
            out.print(f"[dim]{name}: verified against {origin} ({act.id_label} {_s(act.celex)})[/dim]")
        elif status.source == "cache":
            out.print(
                f"[yellow]{name}: {reason}, "
                "text from the cached copy, not re-verified[/yellow]"
            )
        else:
            # The missing SHA-256 below is the consequence of this line, and
            # the two used to sit apart: a reader who saw the gap went looking
            # for a bug in the hashing. There is no verified text to hash, and
            # printing one anyway would assert a verification never made.
            out.print(
                f"[yellow]{name}: {reason} and nothing cached, "
                "text not verifiable: the citations below have no SHA-256[/yellow]"
            )
        if act.note:
            out.print(f"[dim]  {_s(act.note)}[/dim]")
        if status.error:
            out.print(f"[dim]  {_s(status.error)}[/dim]")
    for provision, previous in law.changed.items():
        out.print(f"[yellow]⚠️  Il testo di {_s(provision)} è cambiato dall'ultimo audit[/yellow]")
        out.print(f"[dim]   precedente: {_s(previous)}[/dim]")
    for note in law.notes:
        out.print(f"[yellow]⚠️  {_s(note)}[/yellow]")

    out.print()
    finding = None
    for citation in law.citations:
        if citation.finding != finding:
            finding = citation.finding
            out.print(f"[bold]{_s(FINDING_TITLES[finding])}[/bold]")
            if law.evidence.get(finding):
                out.print(f"[dim]{_s(', '.join(law.evidence[finding]))}[/dim]")
        out.print(visible(format_citation(citation), keep="\n"), markup=False, highlight=False)
        out.print()


def _not_a_domain(value: str) -> str:
    """Why `value` cannot be the name of a domain to analyse; "" when it can.

    A URL went to DNS as `https://example.com/` and to --save as a path; an
    address went to DNS whole.
    """
    if "://" in value:
        host = urlsplit(value).hostname or ""
        return "a URL is not a domain: pass the host name alone" + (f", {host}" if host else "")
    if "@" in value:
        return f"an email address is not a domain: pass the part after the @, {value.rpartition('@')[2]}"
    if any(ch.isspace() for ch in value.strip()):
        return "not a domain name: it has a space inside"
    return ""


def _domain_argument(value: str) -> str:
    """The DOMAIN argument's check: a URL or an address is a usage error."""
    problem = _not_a_domain(value)
    if problem:
        raise typer.BadParameter(visible(problem))
    return value


def _lang_option(value: str) -> str:
    """--lang as `it` or `en`, whatever its case; any other value is a usage error."""
    from mailradar.reporter import language

    try:
        return language(value)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None


def _existing_domain(domain: str) -> str:
    """The domain to analyse: `domain` if DNS knows it, or the variant the user picks.

    Exits 64 when the name is not a valid domain name, and 1 when DNS did not
    answer, when the name does not exist and has no variants to offer, or when
    the user picks none. `check`, `report` and
    `send` share it: `report no-such-domain.example` wrote a letter grading the
    name CRITICAL, and `send` would have mailed security@ it.
    """
    from mailradar.checker import (
        DNSLookupError,
        InvalidDomainError,
        domain_exists,
        find_domain_variants,
        variant_base,
    )

    # Does the domain exist at all
    try:
        with _status(f"[cyan]Checking if {_s(domain)} exists...[/cyan]"):
            exists = domain_exists(domain)
    except InvalidDomainError as e:
        # No resolver is asked and none would help: the name itself is wrong,
        # a usage error like a URL given for a domain
        console.print(f"\n[red]❌ {_s(str(e))}[/red]")
        raise typer.Exit(64) from None
    except DNSLookupError as e:
        # A timeout is not an answer: neither "not found" nor a guess at another domain
        console.print(f"\n[red]❌ {_s(domain)} could not be checked: {_s(str(e))}. "
                      "Try again, or with another DNS resolver.[/red]")
        raise typer.Exit(1) from None

    if not exists:
        console.print(f"\n[yellow]⚠️  Domain [bold]{_s(domain)}[/bold] not found in DNS.[/yellow]")
        if variant_base(domain) is None:
            console.print("[red]❌ Check the domain name.[/red]")
            raise typer.Exit(1)
        console.print("[dim]Scanning TLD variants...[/dim]\n")

        with _status("[cyan]Scanning variants...[/cyan]"):
            variants = find_domain_variants(domain)

        if not variants:
            console.print(f"[red]❌ No variants found for {_s(domain)}. Check the domain name.[/red]")
            raise typer.Exit(1)

        console.print(f"[green]Found {len(variants)} variant(s):[/green]\n")
        for i, v in enumerate(variants, 1):
            console.print(f"  [bold cyan]{i}[/bold cyan]. {_s(v)}")

        console.print()
        # No default: Enter alone analysed variant 1, a domain the user never named
        choice = typer.prompt("Select domain to analyze (number)", type=int)

        if choice < 1 or choice > len(variants):
            console.print("[red]Invalid choice.[/red]")
            raise typer.Exit(1)

        domain = variants[choice - 1]
        console.print(f"\n[dim]Selected: [bold]{_s(domain)}[/bold][/dim]")
    return domain


@app.command()
def check(
    domain: str = typer.Argument(..., help="Domain to analyze", callback=_domain_argument),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show raw DNS records"),
    headers: str = typer.Option(
        None, "--headers",
        help="A message from the domain (.eml): also check the DKIM selectors its signatures name",
    ),
):
    """
    Analyze the email security posture of a domain.
    If the domain does not exist, scan TLD variants and let you choose.
    """
    domain = _existing_domain(domain)
    selectors = _selectors_from(headers, domain) if headers else []

    console.print(f"\n[dim]Analyzing [bold]{_s(domain)}[/bold]...[/dim]")

    with _status("[cyan]Running DNS checks...[/cyan]"):
        report = analyze_domain(domain, dkim_selectors=selectors)

    _print_report(report)

    if verbose:
        console.print("[bold]Raw records:[/bold]")
        # Exactly as published, controls written out: no markup, no highlighting
        if report.dmarc.raw:
            origin = f" (@{report.dmarc.found_at})" if report.dmarc.inherited else ""
            console.print(visible(f"  DMARC{origin}: {report.dmarc.raw}"), markup=False, highlight=False)
        if report.spf.raw:
            console.print(visible(f"  SPF:   {report.spf.raw}"), markup=False, highlight=False)
        if report.dkim.raw:
            console.print(visible(f"  DKIM:  {report.dkim.raw}"), markup=False, highlight=False)
        if report.bimi.raw:
            console.print(visible(f"  BIMI:  {report.bimi.raw}"), markup=False, highlight=False)
        console.print()

    _print_law_check(_law_check(report))

    code = _grade_exit_code(report)
    if code:
        raise typer.Exit(code)


def _selectors_from(path: str, domain: str) -> list[str]:
    """The DKIM selectors the message at `path` was signed with for `domain`, said aloud.

    The message is read, not trusted: only s= values that are DNS names are
    kept, and only from signatures whose d= is the domain analysed.
    """
    from mailradar.checker import dkim_selectors_in

    try:
        with open(path, "rb") as f:
            message = f.read()
    except FileNotFoundError:
        console.print(f"[red]File not found: {_s(path)}[/red]")
        raise typer.Exit(1) from None
    except OSError as e:
        console.print(f"[red]Cannot read {_s(path)}: {_s(str(e.strerror or e))}[/red]")
        raise typer.Exit(1) from None
    selectors = dkim_selectors_in(message, domain)
    if selectors:
        console.print(f"[dim]DKIM selectors from {_s(path)}: {_s(', '.join(selectors))}[/dim]")
    else:
        console.print(f"[yellow]No DKIM signature for {_s(domain)} in {_s(path)}: "
                      f"only the common selectors are checked[/yellow]")
    return selectors


def _grade_exit_code(report: DomainReport) -> int:
    """`check`'s exit code for `report`: 0 EXCELLENT/GOOD, 1 MODERATE/POOR, 2 CRITICAL, 3 no grade.

    An incomplete analysis has a code of its own: 2 told a script "measured
    and found bad" for lookups nobody answered.
    """
    if report.total_score is None:
        return 3
    if report.grade == "CRITICAL":
        return 2
    if report.grade in ("POOR", "MODERATE"):
        return 1
    return 0


def _read_list(path: str) -> list[tuple[int, str]]:
    """(line number, name) for every non-empty line, comments left out.

    utf-8-sig, not utf-8: it consumes a Windows byte order mark if there is one
    and behaves identically when there is not. A comment is a line that starts
    with "#" once stripped, or what follows whitespace and "#" on a line
    (`gpdp.it # Garante`), as in most list formats: before mailradar#143 the
    whole line was looked up and reported "not found in DNS".
    """
    with open(path, encoding="utf-8-sig") as f:
        lines = [re.split(r"\s#", line, maxsplit=1)[0].strip() for line in f]
    return [(number, line) for number, line in enumerate(lines, 1) if line and not line.startswith("#")]


def _same_names(entries: list[tuple[int, str]]) -> dict[str, list[int]]:
    """Each name once, in the order it first appears, with every line that named it.

    `example.com.`, `EXAMPLE.COM` and `example.com` are one domain: case does
    not matter in DNS, and the trailing dot only says the name is absolute. Read
    as three, they were three analyses, three times the queries, and three
    summary rows that all said `example.com` (mailradar#143).
    """
    names: dict[str, list[int]] = {}
    for number, name in entries:
        names.setdefault(name.rstrip(".").lower() or name, []).append(number)
    return names


@app.command()
def batch(
    file: str = typer.Argument(..., help="File with one domain per line"),
):
    """
    Analyze multiple domains from a file.
    """
    try:
        names = _same_names(_read_list(file))
    except FileNotFoundError:
        console.print(f"[red]File not found: {_s(file)}[/red]")
        raise typer.Exit(1) from None
    except UnicodeDecodeError:
        console.print(f"[red]Cannot read {_s(file)}: not valid UTF-8[/red]")
        raise typer.Exit(1) from None
    except OSError as e:
        console.print(f"[red]Cannot read {_s(file)}: {_s(str(e.strerror or e))}[/red]")
        raise typer.Exit(1) from None

    from mailradar.checker import DNSLookupError, domain_exists

    results = []
    failed = []
    for domain in names:
        console.print(f"[dim]Checking {_s(domain)}...[/dim]")
        # check's questions, without its prompt: a batch runs unattended
        problem = _not_a_domain(domain)
        if not problem:
            try:
                problem = "" if domain_exists(domain) else "not found in DNS"
            except DNSLookupError as e:
                problem = f"could not be checked: {e}"
        if problem:
            console.print(f"[red]❌ {_s(domain)}: {_s(problem)}[/red]")
            failed.append(domain)
            continue
        try:
            report = analyze_domain(domain)
        except Exception as e:
            # One difficult domain must not stop the whole batch
            console.print(f"[red]❌ {_s(domain)}: analysis failed — {_s(str(e))}[/red]")
            failed.append(domain)
            continue
        results.append(report)
        _print_report(report)

    # Summary table
    console.print(Panel("[bold]Batch Summary[/bold]", border_style="cyan"))
    summary = Table(box=box.SIMPLE)
    summary.add_column("Domain")
    summary.add_column("Score", justify="right")
    summary.add_column("Grade")

    # Worst first; the incomplete analyses after the graded ones, not among the zeros
    for r in sorted(results, key=lambda x: (x.total_score is None, x.total_score or 0)):
        color = _score_color(r.total_score)
        summary.add_row(
            _s(r.domain),
            f"[{color}]{'N/A' if r.total_score is None else r.total_score}[/{color}]",
            f"{_grade_emoji(r.grade)} {r.grade}"
        )

    console.print(summary)

    repeated = {name: lines for name, lines in names.items() if len(lines) > 1}
    if repeated:
        console.print("[dim]Named on more than one line, analysed once:[/dim]")
        for name, lines in repeated.items():
            console.print(f"[dim]  {_s(name)}: lines {', '.join(map(str, lines))}[/dim]")

    if failed:
        console.print(f"[red]Failed ({len(failed)}): {_s(', '.join(failed))}[/red]")

    # It exited 0 whatever it found. The highest of the codes `check` would
    # give each domain, a domain that could not be analysed counting 1 as it
    # does in `check`: 0 only when every domain was analysed and graded GOOD
    # or better.
    code = max([_grade_exit_code(r) for r in results] + [1] * bool(failed), default=0)
    if code:
        raise typer.Exit(code)


def main():
    app()


def _refuse_unverified(analysis: DomainReport) -> None:
    """A report goes to the domain's owner: it must not state what DNS did not answer."""
    errors = _unverified(analysis)
    if errors:
        console.print(f"[red]❌ Report not generated, the analysis is incomplete: {_s(errors[0])}[/red]")
        console.print("[dim]Try again later, or with another resolver.[/dim]")
        raise typer.Exit(1)


@app.command()
def report(
    domain: str = typer.Argument(..., help="Domain to analyze and generate report for", callback=_domain_argument),
    lang: str = typer.Option("it", "--lang", "-l", help="Report language: it or en", callback=_lang_option),
    sender_name: str = typer.Option("[NOME]", "--name", help="Sender name"),
    sender_role: str = typer.Option("[RUOLO]", "--role", help="Sender role"),
    sender_org: str = typer.Option("[ORGANIZZAZIONE]", "--org", help="Sender organization"),
    save: bool = typer.Option(False, "--save", "-s", help="Save report to file"),
):
    """
    Generate a ready-to-send email report for a domain.
    """
    from mailradar.reporter import generate_report, save_report

    domain = _existing_domain(domain)
    console.print(f"\n[dim]Analyzing [bold]{_s(domain)}[/bold]...[/dim]")

    with _status("[cyan]Running DNS checks...[/cyan]"):
        from mailradar.checker import analyze_domain
        analysis = analyze_domain(domain)

    _print_report(analysis)
    _refuse_unverified(analysis)

    console.print("[bold cyan]📧 Generating email report...[/bold cyan]\n")
    text = generate_report(
        analysis,
        lang=lang,
        sender_name=sender_name,
        sender_role=sender_role,
        sender_org=sender_org,
    )

    console.print(Panel(Text(text), title=f"📧 Report — {_s(analysis.domain)}", border_style="cyan"))
    console.print()
    _print_law_check(_law_check(analysis))

    if save:
        try:
            # The analysed name, not the argument: the file name is built from it
            path = save_report(text, analysis.domain, lang)
        except OSError as e:
            console.print(f"\n[red]❌ Report not saved: {_s(e.strerror or e)} "
                          f"({_s(e.filename or 'current directory')})[/red]")
            raise typer.Exit(1) from None
        console.print(f"\n[green]✅ Report saved to: {_s(path)}[/green]")


def _uses_starttls(port: int, starttls: bool) -> bool:
    """STARTTLS when asked for, and on 587, the submission port (RFC 6409), where implicit TLS never works."""
    return starttls or port == 587


@app.command()
def send(
    domain: str = typer.Argument(..., help="Domain to analyze and send report to", callback=_domain_argument),
    lang: str = typer.Option("it", "--lang", "-l", help="Report language: it or en", callback=_lang_option),
    sender_name: str = typer.Option("[NOME]", "--name", help="Sender name"),
    sender_role: str = typer.Option("[RUOLO]", "--role", help="Sender role"),
    sender_org: str = typer.Option("[ORGANIZZAZIONE]", "--org", help="Sender organization"),
    smtp_host: str = typer.Option(None, "--smtp-host", help="SMTP host (e.g. mail.infomaniak.com)"),
    smtp_port: int = typer.Option(465, "--smtp-port", help="SMTP port: 465 is implicit TLS, 587 STARTTLS"),
    smtp_starttls: bool = typer.Option(
        False, "--smtp-starttls",
        help="Connect in plain text and upgrade with STARTTLS (the default on port 587); "
             "otherwise TLS starts with the connection (SMTPS)",
    ),
    smtp_user: str = typer.Option(None, "--smtp-user", help="SMTP username"),
    smtp_pass: str = typer.Option(None, "--smtp-pass", help="SMTP password", envvar="MAILRADAR_SMTP_PASS"),
    from_email: str = typer.Option(None, "--from", help="Sender email (e.g. security@yourdomain.com)"),
    sign: bool = typer.Option(False, "--sign", help="Sign the report with your GPG private key"),
    gpg_fingerprint: str = typer.Option(
        None, "--gpg-fingerprint", metavar="FPR",
        help="Fingerprint of the recipient's key, confirmed with the domain: required to encrypt to a key "
             "found on a keyserver that does not verify addresses (keyserver.ubuntu.com), and must match it",
    ),
):
    """
    Analyze a domain and send the report to its security/DPO contact.

    Logic:
    1. If GPG key found on keyservers → encrypt report and send to key owner
    2. If no GPG but SMTP configured → send plaintext to security@/dpo@/postmaster@
    3. If no SMTP → print report for manual copy-paste
    """
    from mailradar.checker import analyze_domain
    from mailradar.reporter import generate_report
    from mailradar.sender import SMTPConfig, send_report, unconfirmed_key

    if sign and not from_email:
        # It signed nothing and said nothing; before the analysis, which costs
        # keyserver lookups against a limit
        raise typer.BadParameter("needs --from, the address whose private key signs the report",
                                 param_hint="'--sign'")

    delivering = all([smtp_host, smtp_user, smtp_pass, from_email])
    placeholders = [option for option, value, default in (
        ("--name", sender_name, "[NOME]"), ("--role", sender_role, "[RUOLO]"),
        ("--org", sender_org, "[ORGANIZZAZIONE]")) if value == default]
    if delivering and placeholders:
        # They went to a third party as the signature and the display name.
        # Before the analysis, which costs keyserver lookups against a limit;
        # a report printed for a manual send still takes them, to be edited.
        console.print(f"[red]❌ Not sent: {', '.join(placeholders)} still "
                      f"{'hold their placeholders' if len(placeholders) > 1 else 'holds its placeholder'}, "
                      f"which would reach the recipient as written.[/red]")
        raise typer.Exit(1)

    domain = _existing_domain(domain)
    console.print(f"\n[dim]Analyzing [bold]{_s(domain)}[/bold]...[/dim]")

    with _status("[cyan]Running DNS checks...[/cyan]"):
        analysis = analyze_domain(domain)
    # The name as analysed from here on: `StartPage.COM.` went to the SMTP
    # server as RCPT TO:<security@StartPage.COM.>
    domain = analysis.domain

    _print_report(analysis)
    _refuse_unverified(analysis)
    if delivering and not analysis.gpg.found and analysis.gpg.error:
        # "Not verified" is not "absent": a keyserver that did not answer may
        # hold the recipient's key, and plaintext is what a key would prevent.
        console.print(f"[red]❌ Not sent in plaintext: the GPG check is not verified "
                      f"({_s(analysis.gpg.error)}), and a key may exist. Try again later.[/red]")
        raise typer.Exit(1)

    # Generate report text
    report_text = generate_report(
        analysis,
        lang=lang,
        sender_name=sender_name,
        sender_role=sender_role,
        sender_org=sender_org,
    )

    # Build SMTP config if provided
    smtp_config = None
    if all([smtp_host, smtp_user, smtp_pass, from_email]):
        smtp_config = SMTPConfig(
            host=smtp_host,
            port=smtp_port,
            username=smtp_user,
            password=smtp_pass,
            from_email=from_email,
            from_name=sender_name,
            use_tls=not _uses_starttls(smtp_port, smtp_starttls),
        )

    passphrase = None
    if sign and not unconfirmed_key(analysis.gpg, gpg_fingerprint):
        # Here, not under the spinner below: getpass there had its prompt
        # redrawn over by the status line
        passphrase = typer.prompt(f"GPG passphrase for {visible(from_email)}", hide_input=True,
                                  default="", show_default=False)

    # Smart send
    console.print("\n[bold cyan]📧 Sending report...[/bold cyan]")
    with _status("[cyan]Checking GPG keys and sending...[/cyan]"):
        result = send_report(
            domain=domain,
            report_text=report_text,
            gpg_result=analysis.gpg,
            config=smtp_config,
            lang=lang,
            sign=sign,
            sign_email=from_email,
            fingerprint=gpg_fingerprint,
            sign_passphrase=passphrase,
        )

    if result.method == "gpg-encrypted" or result.method == "plaintext":
        console.print(f"\n[green]{_s(result.message)}[/green]")
        console.print(f"[dim]Method: {result.method} | Recipient: {_s(result.recipient)}[/dim]")

    elif result.method == "manual-gpg":
        if result.error:
            console.print(f"\n[red]❌ Not sent: SMTP delivery to {_s(result.recipient)} failed — "
                          f"{_s(result.error)}[/red]")
        else:
            console.print(f"\n[yellow]⚠️  GPG key found for {_s(result.recipient)} but no SMTP configured."
                          "[/yellow]")
        console.print("[yellow]   Send this GPG-encrypted text manually:[/yellow]\n")
        console.print(Panel(Text(visible(result.message, keep="\n")), title="🔐 GPG Encrypted Report",
                            border_style="yellow"))

    elif result.method == "smtp-failed":
        console.print(f"\n[red]❌ Not sent: SMTP delivery failed — {_s(result.error)}[/red]")
        console.print("[red]   Nothing else was tried: check the SMTP settings, or send the report below "
                      f"manually to {_s(result.recipient)}.[/red]\n")
        console.print(Panel(Text(visible(report_text, keep="\n")),
                            title=f"📧 Report — {_s(analysis.domain)} (copy-paste)", border_style="red"))

    elif result.method == "gpg-unverified":
        console.print(f"\n[red]❌ Not sent, not encrypted and not sent in plaintext: {_s(result.message)}.[/red]")
        if not analysis.gpg.found:
            console.print("[yellow]   There is no key to encrypt to: run again without --gpg-fingerprint "
                          "to send the report as the analysis allows.[/yellow]")
            raise typer.Exit(1)
        fingerprint = _s(analysis.gpg.fingerprint or "<FPR>")
        console.print(
            f"[yellow]   Confirm the fingerprint with {_s(analysis.domain)} through another channel, then run "
            f"again with --gpg-fingerprint {fingerprint}; or encrypt the report below yourself to the key "
            f"you confirmed (gpg --encrypt --armor --recipient {fingerprint}) and send it to "
            f"{_s(result.recipient)}.[/yellow]\n"
        )
        console.print(Panel(Text(visible(report_text, keep="\n")),
                            title=f"📧 Report — {_s(analysis.domain)} (unencrypted: do not send as it is)",
                            border_style="red"))
        raise typer.Exit(1)

    elif result.method == "sign-failed":
        console.print(f"\n[red]❌ Not sent: {_s(result.message)}.[/red]")
        console.print("[red]   Run again with the right passphrase, or without --sign.[/red]")
        raise typer.Exit(1)

    elif result.method == "gpg-failed":
        console.print(f"\n[red]❌ {_s(result.message)}[/red]")
        console.print("[red]   Plaintext was not sent. Check your gpg installation, "
                      "or send the report below manually.[/red]\n")
        console.print(Panel(Text(report_text), title=f"📧 Report — {_s(domain)} (unencrypted)", border_style="red"))
        raise typer.Exit(1)

    else:
        console.print("\n[yellow]ℹ️  No SMTP configured: nothing was sent.[/yellow]")
        console.print(f"[dim]Send manually to: {_s(result.recipient)}[/dim]\n")
        console.print(Panel(Text(report_text), title=f"📧 Report — {_s(domain)} (copy-paste)", border_style="cyan"))

    if smtp_config is not None and not result.sent:
        # Delivery was asked for and did not happen, whichever branch said so
        raise typer.Exit(1)


@app.command()
def discover(
    domain: str = typer.Argument(..., help="Domain to discover email addresses for", callback=_domain_argument),
    no_gpg: bool = typer.Option(False, "--no-gpg", help="Skip GPG key check"),
):
    """
    Discover all email addresses associated with a domain.
    Sources: Certificate Transparency (crt.sh), website scraping, RDAP/WHOIS.
    """
    from mailradar.checker import _labels
    from mailradar.discover import discover as run_discover

    # As analyze_domain does: `Example.COM.` is example.com, for crt.sh, the
    # website, RDAP and the keyservers alike
    domain = ".".join(_labels(domain))
    if "." not in domain:
        console.print(f"[red]Invalid domain: {_s(domain)} — missing TLD[/red]")
        raise typer.Exit(1)

    console.print(f"\n[dim]Discovering email addresses for [bold]{_s(domain)}[/bold]...[/dim]")

    with _status("[cyan]Querying crt.sh, website and RDAP...[/cyan]"):
        result = run_discover(domain, check_gpg=not no_gpg)

    if not result.emails and not result.candidates:
        console.print(f"\n[yellow]No email addresses found for {_s(domain)}[/yellow]")
        raise typer.Exit(0)

    # Separa sottodomini da email
    subdomains = result.sources.get("crt.sh subdomains", [])
    email_sources = {k: v for k, v in result.sources.items() if k != "crt.sh subdomains"}

    if subdomains:
        console.print(f"\n[bold cyan]Subdomains found via crt.sh ({len(subdomains)}):[/bold cyan]")
        for sub in sorted(set(subdomains)):
            console.print(visible(f"  • {sub}"), highlight=False, markup=False)
        console.print()

    # Email addresses
    if result.emails:
        console.print(f"[bold green]Found {len(result.emails)} email address(es) for {_s(domain)}:[/bold green]\n")
    else:
        console.print(f"[yellow]No email addresses found in public sources for {_s(domain)}.[/yellow]\n")
    if result.candidates:
        console.print(f"[dim]{len(result.candidates)} common role address(es) guessed — not verified.[/dim]\n")

    for source, items in email_sources.items():
        emails_only = [e for e in items if "@" in e]
        if not emails_only:
            continue
        label = "[dim](candidate — not verified)[/dim]" if source == "common contacts" else ""
        console.print(f"[bold cyan]Source: {source}[/bold cyan] {label}")
        for email in sorted(emails_only):
            gpg_icon = "🔐" if email in result.gpg_capable else "  "
            console.print(f"  {gpg_icon} {_s(email)}")
        console.print()

    if result.gpg_capable:
        console.print(f"[bold green]🔐 GPG-capable addresses ({len(result.gpg_capable)}):[/bold green]")
        for email in result.gpg_capable:
            console.print(f"  • {_s(email)}")
        console.print()
        console.print("[dim]These addresses can receive GPG-encrypted reports.[/dim]")
    elif not result.gpg_unverified and not no_gpg:
        console.print("[dim]No GPG public keys found for any address.[/dim]")
    if result.gpg_unverified:
        # "No key" only when the keyservers said so: a 429 or a timeout says nothing
        console.print(f"[yellow]⚠️  GPG not verified for {len(result.gpg_unverified)} address(es) — no keyserver "
                      f"answered (rate limit or timeout), a key may exist: "
                      f"{_s(', '.join(result.gpg_unverified))}[/yellow]")

    console.print()


# Last, after every command: placed above `report`, it ran the app before
# report, send and discover were registered
if __name__ == "__main__":
    main()
