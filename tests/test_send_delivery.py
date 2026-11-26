"""
`send` against real local servers: what it delivers, to whom, and what it
refuses (tests/replay.py: SMTP on 127.0.0.1, DNS and keyservers replayed from
recordings). No mail leaves the machine, and gpg never sees the user's keyring.
"""
from __future__ import annotations

import email
import re
import secrets

import pytest
from typer.testing import CliRunner

from mailradar.cli import app
from mailradar.gpg import lookup_gpg
from mailradar.sender import SMTPConfig, send_report
from tests.names import mentions

FROM = "security@maksimtech.com"
NAMED = ["--name", "Mario Rossi", "--role", "Security engineer", "--org", "Maksimtech"]
ENV = {"COLUMNS": "300"}

# keyserver.ubuntu.com's key for security@example.com (keyservers_example_com.json, recorded)
EXAMPLE_COM_FPR = "3BB547F4A09EDE1C40981268526A5BBFE98ED6E7"
# keyserver.ubuntu.com's key for security@gmail.com (keyservers_gmail_com.json, recorded)
GMAIL_COM_FPR = "6902757CCE90C14EA12A5A5E44789306437E75D5"


@pytest.fixture
def server(smtp_server, trusted_ca, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_ca.path))
    return smtp_server("tls", trusted_ca.server_context("127.0.0.1"))


@pytest.fixture(autouse=True)
def _no_user_keyring(tmp_path, monkeypatch):
    """gpg, if any test reaches it, works in an empty keyring of its own."""
    home = tmp_path / "gnupg"
    home.mkdir()
    monkeypatch.setenv("GNUPGHOME", str(home))
    yield
    import subprocess
    subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True, check=False)


def _config(server) -> SMTPConfig:
    return SMTPConfig(host="127.0.0.1", port=server.port, username=FROM, password=secrets.token_urlsafe(16),
                      from_email=FROM, from_name="Mario Rossi", use_tls=True)


def _send(domain, smtp, *extra, input=None):
    return CliRunner().invoke(app, [
        "send", domain, "--smtp-host", "127.0.0.1", "--smtp-port", str(smtp.port),
        "--smtp-user", FROM, "--smtp-pass", secrets.token_urlsafe(16), "--from", FROM, *NAMED, *extra,
    ], env=ENV, input=input)


def _flat(output: str) -> str:
    """The words of `output`, without Rich's colours: on GitHub Actions Rich colours
    Typer's usage panel, and `--from` arrives as `-` and `-from` between escapes."""
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", output).split())


def _recipients(server) -> list[str]:
    """The address of every RCPT TO the server received, as the client wrote it."""
    return [c.partition(":")[2].strip().strip("<>") for c in server.commands if c.upper().startswith("RCPT")]


def _body(message: bytes) -> str:
    """The text of the message's one part, transfer encoding undone."""
    [part] = [p for p in email.message_from_bytes(message).walk() if not p.is_multipart()]
    return part.get_payload(decode=True).decode("utf-8")


def _gpg_usable() -> bool:
    from tests.test_sender import _gpg_can_generate_a_key
    return _gpg_can_generate_a_key()


def _example_com(dns_replay, http_replay):
    dns_replay("example_com", "example_com_dkim_more_selectors")
    http_replay("example_com", "keyservers_example_com")


# ─── An unverified key needs the user's confirmation ─────────────────────────

def test_a_key_nobody_verified_is_not_encrypted_to(server, http_replay):
    """keyserver.ubuntu.com lists, for security@gmail.com, a key anyone could have uploaded (recorded)."""
    http_replay("keyservers_gmail_com")
    gpg = lookup_gpg("gmail.com")

    result = send_report("gmail.com", "report", gpg, config=_config(server))

    assert result.sent is False
    assert result.method == "gpg-unverified"
    assert GMAIL_COM_FPR in result.message
    assert server.connections == 0


def test_a_fingerprint_that_does_not_match_is_refused(server, http_replay):
    http_replay("keyservers_gmail_com")
    gpg = lookup_gpg("gmail.com")

    result = send_report("gmail.com", "report", gpg, config=_config(server), fingerprint=EXAMPLE_COM_FPR)

    assert result.method == "gpg-unverified"
    assert "does not match" in result.message
    assert server.connections == 0


def test_send_refuses_an_unverified_key_and_says_how_to_go_on(server, dns_replay, http_replay):
    _example_com(dns_replay, http_replay)

    result = _send("example.com", server)

    assert result.exit_code == 1, result.output
    assert server.connections == 0
    out = _flat(result.output)
    assert EXAMPLE_COM_FPR in out
    assert "does not verify" in out
    assert "--gpg-fingerprint" in out
    assert "Report sent" not in out


def test_send_refuses_a_fingerprint_that_is_not_the_key_found(server, dns_replay, http_replay):
    _example_com(dns_replay, http_replay)

    result = _send("example.com", server, "--gpg-fingerprint", GMAIL_COM_FPR)

    assert result.exit_code == 1, result.output
    assert server.connections == 0
    assert "does not match" in _flat(result.output)


@pytest.mark.skipif(not _gpg_usable(), reason="gpg is absent, or cannot keep a keyring where tempfile puts it")
def test_with_the_fingerprint_confirmed_the_report_goes_encrypted(server, dns_replay, http_replay):
    """The same key, its fingerprint confirmed: encrypted to it, and sent to the address its uid carries."""
    _example_com(dns_replay, http_replay)

    result = _send("example.com", server, "--gpg-fingerprint", EXAMPLE_COM_FPR.lower())

    assert result.exit_code == 0, result.output
    assert len(server.messages) == 1
    assert "BEGIN PGP MESSAGE" in _body(server.messages[0])
    assert _recipients(server) == ["security@example.com"]


def test_without_smtp_an_unverified_key_is_not_used_either(dns_replay, http_replay):
    """The encrypted text printed for a manual send would be encrypted to the same unverified key."""
    _example_com(dns_replay, http_replay)

    result = CliRunner().invoke(app, ["send", "example.com"], env=ENV)

    assert result.exit_code == 1, result.output
    assert "BEGIN PGP MESSAGE" not in result.output
    assert EXAMPLE_COM_FPR in _flat(result.output)


def test_a_verified_keyserver_that_did_not_answer_is_reported(http_replay):
    """keys.openpgp.org answered 429 for security@gmail.com, keyserver.ubuntu.com listed an unverified key
    (keyservers_gmail_com_openpgp_429.json, derived): the 429 used to vanish once ubuntu answered."""
    http_replay("keyservers_gmail_com_openpgp_429")
    gpg = lookup_gpg("gmail.com")

    assert gpg.found is True and gpg.verified is False
    assert "429" in gpg.unanswered
    assert any(mentions(issue, "keys.openpgp.org") and "did not answer" in issue for issue in gpg.issues)


def test_send_says_the_verifying_keyserver_did_not_answer(server, http_replay):
    http_replay("keyservers_gmail_com_openpgp_429")
    gpg = lookup_gpg("gmail.com")

    result = send_report("gmail.com", "report", gpg, config=_config(server))

    assert result.method == "gpg-unverified"
    assert mentions(result.message, "keys.openpgp.org") and "429" in result.message


# ─── --sign ──────────────────────────────────────────────────────────────────

def _startpage_com(dns_replay, http_replay):
    """startpage.com as recorded: every keyserver answers, none holds a key for its contacts."""
    dns = dns_replay("startpage_com", "startpage_com_tlsa", "startpage_com_dkim_selectors", "startpage_com_exists")
    http_replay("startpage_com", "startpage_com_keyservers_index")
    return dns


def test_a_signature_that_fails_stops_the_send(server, dns_replay, http_replay):
    """An empty keyring (GNUPGHOME, above) holds no key to sign with: the report went out unsigned."""
    _startpage_com(dns_replay, http_replay)

    result = _send("startpage.com", server, "--sign", input="not-the-passphrase\n")

    assert result.exit_code == 1, result.output
    assert server.connections == 0
    assert "not signed" in _flat(result.output).lower()


def test_sign_without_from_is_refused_before_the_analysis(dns_replay, http_replay):
    """--sign without --from signed nothing and said nothing."""
    dns = _startpage_com(dns_replay, http_replay)

    result = CliRunner().invoke(app, ["send", "startpage.com", "--sign"], env=ENV)

    assert result.exit_code == 64, result.output
    assert "--from" in _flat(result.output)
    assert dns.queries == []


def test_the_passphrase_is_asked_before_sending_starts(server, dns_replay, http_replay):
    """getpass ran under the spinner of "Checking GPG keys and sending...", which redraws over the prompt."""
    _startpage_com(dns_replay, http_replay)

    result = _send("startpage.com", server, "--sign", input="not-the-passphrase\n")

    out = result.output
    assert "GPG passphrase for security@maksimtech.com" in out
    assert out.index("GPG passphrase for") < out.index("Sending report")


# ─── SMTP failures ───────────────────────────────────────────────────────────

AUTH_REJECTED = {"AUTH": b"535 5.7.8 Authentication credentials invalid\r\n"}
QUIT_250 = {"QUIT": b"250 2.0.0 OK\r\n"}


def _auths(server) -> int:
    return sum(command.upper().startswith("AUTH") for command in server.commands)


@pytest.fixture
def smtp(smtp_server, trusted_ca, monkeypatch):
    """smtp(replies=..., refused=...): an SMTPS server on 127.0.0.1 with a certificate the client trusts."""
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_ca.path))
    return lambda **kwargs: smtp_server("tls", trusted_ca.server_context("127.0.0.1"), **kwargs)


def test_a_wrong_password_is_tried_once(smtp):
    """535 to AUTH meant "try the next address": five logins on five connections, a lockout risked."""
    server = smtp(replies=AUTH_REJECTED)

    result = send_report("startpage.com", "report", lookup_gpg_none(), config=_config(server))

    assert result.sent is False
    assert result.method == "smtp-failed"
    assert _auths(server) == 1
    assert server.connections == 1


def test_a_certificate_nobody_trusts_is_met_once(smtp_server, tmp_path, monkeypatch):
    from tests.replay import CertificateAuthority
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    server = smtp_server("tls", CertificateAuthority(tmp_path, "untrusted-ca").server_context("127.0.0.1"))

    result = send_report("startpage.com", "report", lookup_gpg_none(), config=_config(server))

    assert result.method == "smtp-failed"
    assert server.connections == 1


def test_a_refused_recipient_moves_on_to_the_next_address(smtp):
    """The one failure that is about the address: 550 to RCPT for security@, dpo@ accepted."""
    server = smtp(refused=["security@startpage.com"])

    result = send_report("startpage.com", "report", lookup_gpg_none(), config=_config(server))

    assert result.sent is True
    assert result.recipient == "dpo@startpage.com"
    assert len(server.messages) == 1


def test_a_message_accepted_after_data_is_sent_whatever_quit_says(smtp):
    """250 to DATA, then 250 instead of 221 to QUIT: SMTP.__exit__ raised, and the report went five times."""
    server = smtp(replies=QUIT_250)

    result = send_report("startpage.com", "report", lookup_gpg_none(), config=_config(server))

    assert result.sent is True
    assert len(server.messages) == 1


def test_send_stops_at_a_wrong_password_and_exits_nonzero(smtp, dns_replay, http_replay):
    _startpage_com(dns_replay, http_replay)
    server = smtp(replies=AUTH_REJECTED)

    result = _send("startpage.com", server)

    assert result.exit_code == 1, result.output
    assert _auths(server) == 1
    out = _flat(result.output)
    assert "No SMTP configured" not in out
    assert "535" in out


def test_send_says_sent_when_quit_is_answered_250(smtp, dns_replay, http_replay):
    _startpage_com(dns_replay, http_replay)
    server = smtp(replies=QUIT_250)

    result = _send("startpage.com", server)

    assert result.exit_code == 0, result.output
    assert len(server.messages) == 1
    assert "Report sent in plaintext to security@startpage.com" in _flat(result.output)


@pytest.mark.skipif(not _gpg_usable(), reason="gpg is absent, or cannot keep a keyring where tempfile puts it")
def test_an_encrypted_report_smtp_refused_is_not_called_no_smtp(smtp, dns_replay, http_replay):
    """The encrypted text was printed under "no SMTP configured", with exit code 0, after SMTP had failed."""
    _example_com(dns_replay, http_replay)
    server = smtp(replies=AUTH_REJECTED)

    result = _send("example.com", server, "--gpg-fingerprint", EXAMPLE_COM_FPR)

    assert result.exit_code == 1, result.output
    out = _flat(result.output)
    assert "no SMTP configured" not in out.lower().replace("smtp", "SMTP")
    assert "535" in out
    assert "BEGIN PGP MESSAGE" in out


def lookup_gpg_none():
    """What lookup_gpg answers for startpage.com (startpage_com_keyservers_index.json): every keyserver, no key."""
    from mailradar.gpg import GPGResult
    return GPGResult(issues=["No GPG public key found for startpage.com on any keyserver"])


# ─── STARTTLS ────────────────────────────────────────────────────────────────

def test_send_can_use_starttls(smtp_server, trusted_ca, monkeypatch, dns_replay, http_replay):
    """use_tls was never set from the command line: on a submission port (587) the TLS handshake met a
    plain-text greeting, five times, and the command exited 0."""
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_ca.path))
    server = smtp_server("starttls", trusted_ca.server_context("127.0.0.1"))
    _startpage_com(dns_replay, http_replay)

    result = _send("startpage.com", server, "--smtp-starttls")

    assert result.exit_code == 0, result.output
    assert "STARTTLS" in [command.upper() for command in server.commands]
    assert len(server.messages) == 1


def test_implicit_tls_against_a_starttls_server_fails_once_and_says_so(
        smtp_server, trusted_ca, monkeypatch, dns_replay, http_replay):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_ca.path))
    server = smtp_server("starttls", trusted_ca.server_context("127.0.0.1"))
    _startpage_com(dns_replay, http_replay)

    result = _send("startpage.com", server)

    assert result.exit_code == 1, result.output
    assert server.connections == 1


@pytest.mark.parametrize("port,flag,starttls", [(465, False, False), (587, False, True), (2525, True, True)])
def test_port_587_means_starttls(port, flag, starttls):
    """587 is the submission port (RFC 6409), where TLS starts with STARTTLS: implicit TLS there never works."""
    from mailradar.cli import _uses_starttls
    assert _uses_starttls(port, flag) is starttls


# ─── The domain as analysed, not as typed ────────────────────────────────────

def test_send_writes_to_the_normalised_domain(smtp, dns_replay, http_replay):
    """`send StartPage.COM.` sent RCPT TO:<security@StartPage.COM.>."""
    _startpage_com(dns_replay, http_replay)
    server = smtp()

    result = _send("StartPage.COM.", server)

    assert result.exit_code == 0, result.output
    assert _recipients(server) == ["security@startpage.com"]
    message = email.message_from_bytes(server.messages[0])
    assert "— startpage.com —" in str(email.header.make_header(email.header.decode_header(message["Subject"])))


def test_the_manual_report_is_titled_with_the_normalised_domain(dns_replay, http_replay):
    _startpage_com(dns_replay, http_replay)

    result = CliRunner().invoke(app, ["send", "StartPage.COM."], env=ENV)

    assert "Report — startpage.com" in result.output
    assert "StartPage.COM" not in result.output.split("Analyzing", 1)[1].split("\n", 1)[1]


def test_discover_normalises_its_input():
    from unittest.mock import patch

    from mailradar.discover import DiscoveryResult
    with patch("mailradar.discover.discover", return_value=DiscoveryResult(domain="startpage.com")) as run:
        CliRunner().invoke(app, ["discover", "StartPage.COM.", "--no-gpg"], env=ENV)
    run.assert_called_once_with("startpage.com", check_gpg=False)


# ─── The mailed body ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("lang,label", [("it", "Oggetto:"), ("en", "Subject:")])
def test_the_mailed_body_does_not_repeat_the_subject(smtp, dns_replay, http_replay, lang, label):
    """The letter opens with a "Subject: …" line for whoever copies it by hand; mailed, it came under the
    Subject header as the body's first line."""
    _startpage_com(dns_replay, http_replay)
    server = smtp()

    result = _send("startpage.com", server, "--lang", lang)

    assert result.exit_code == 0, result.output
    body = _body(server.messages[0])
    assert not body.lstrip().startswith(label), body[:80]
    assert body.lstrip().startswith("Gentile" if lang == "it" else "Dear")


def test_a_fingerprint_with_no_key_found_does_not_turn_into_plaintext(smtp):
    """--gpg-fingerprint says the user expects encryption: with no key found, plaintext is not what was asked."""
    server = smtp()

    result = send_report("startpage.com", "report", lookup_gpg_none(), config=_config(server),
                         fingerprint=EXAMPLE_COM_FPR)

    assert result.sent is False
    assert result.method == "gpg-unverified"
    assert server.connections == 0
