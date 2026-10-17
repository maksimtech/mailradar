"""
MailRadar — `send` builds a message a mail server would accept, and never sends
in plaintext what it could not check (audit F01, F02, 2026-10-17)

F01, in a dry run of `send` against a server on 127.0.0.1: the envelope said
`MAIL FROM:<>`, the message had no `Date` and no `Message-ID`, and `[NOME]`
went out as both display name and signature. The cause: `From` was built as
`f"{name} <{address}>"` and smtplib took the envelope from it — `[` and `]`
are RFC 5322 specials, so "[NOME] <a@b>" parses to no address at all, and
"Rossi, Mario <a@b>" to "Rossi". `MAIL FROM:<>` is the bounce reverse-path
(RFC 5321 §4.5.5), and RFC 5322 §3.6 requires `Date`.

F02, in the same dry run: keys.openpgp.org answered HTTP 429, the GPG check
came out "not verified", and the report went out in plaintext anyway — while
the project's own rule is that "not verified" is not "absent".

Every server here is real and local: SMTP on 127.0.0.1 (tests/replay.py),
DNS and keyservers replayed from recordings. No mail leaves the machine.
"""
from __future__ import annotations

import email
import email.utils
import secrets

import pytest
from typer.testing import CliRunner

from mailradar.cli import app
from mailradar.sender import SMTPConfig, _send_smtp

FROM = "security@maksimtech.com"


@pytest.fixture
def server(smtp_server, trusted_ca, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_ca.path))
    return smtp_server("tls", trusted_ca.server_context("127.0.0.1"))


def _config(server, name="MailRadar") -> SMTPConfig:
    return SMTPConfig(host="127.0.0.1", port=server.port, username=FROM, password=secrets.token_urlsafe(16),
                      from_email=FROM, from_name=name, use_tls=True)


def _envelope_sender(server) -> str:
    [command] = [c for c in server.commands if c.lower().startswith("mail from:")]
    return command.split(":", 1)[1].split()[0]


# ─── F01: the message ────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["[NOME]", "Rossi, Mario", "Jane Doe"])
def test_the_envelope_sender_is_the_from_address_whatever_the_display_name(server, name):
    assert _send_smtp(_config(server, name), "security@example.com", "s", "body") is True

    assert _envelope_sender(server) == f"<{FROM}>"


@pytest.mark.parametrize("name", ["[NOME]", "Rossi, Mario"])
def test_the_from_header_reads_back_as_the_name_and_the_address(server, name):
    _send_smtp(_config(server, name), "security@example.com", "s", "body")

    message = email.message_from_bytes(server.messages[0])
    assert email.utils.getaddresses([message["From"]]) == [(name, FROM)]


def test_the_message_carries_date_and_message_id(server):
    _send_smtp(_config(server), "security@example.com", "s", "body")

    message = email.message_from_bytes(server.messages[0])
    assert email.utils.parsedate_to_datetime(message["Date"]) is not None
    assert message["Message-ID"].endswith("@maksimtech.com>")


# ─── F01: placeholders, F02: plaintext ───────────────────────────────────────

def _send(domain, smtp, *extra):
    return CliRunner().invoke(app, [
        "send", domain, "--smtp-host", "127.0.0.1", "--smtp-port", str(smtp.port),
        "--smtp-user", FROM, "--smtp-pass", secrets.token_urlsafe(16), "--from", FROM, *extra,
    ], env={"COLUMNS": "200"})


NAMED = ["--name", "Mario Rossi", "--role", "Security engineer", "--org", "Maksimtech"]


def test_send_refuses_to_deliver_the_placeholders(server, dns_replay, http_replay):
    """Left to their defaults, --name, --role and --org went to a third party as
    "[NOME]", "[RUOLO]", "[ORGANIZZAZIONE]". Refused before anything is asked of
    the network; printing the report for a manual send still takes them."""
    dns_replay("example_com", "example_com_dkim_more_selectors")
    http_replay("example_com", "keyservers_example_com")

    result = _send("example.com", server)

    assert result.exit_code == 1
    assert server.connections == 0
    assert "--name" in result.output


def test_send_does_not_go_plaintext_when_a_keyserver_did_not_answer(server, dns_replay, http_replay):
    """example.com as recorded: its DNS, and keys.openpgp.org's 404 for each of
    its contacts (example_com.json, keys_openpgp_org_example_com_contacts.json).
    keyserver.ubuntu.com does not answer — a recorded ReadTimeout, filed under
    this request (keyserver_ubuntu_example_com_no_answer.json, derived). Nothing
    proves there is no key, so nothing may be sent in plaintext."""
    dns_replay("example_com", "example_com_dkim_more_selectors")
    http_replay("example_com", "keys_openpgp_org_example_com_contacts", "keyserver_ubuntu_example_com_no_answer")

    result = _send("example.com", server, *NAMED)

    assert result.exit_code == 1, result.output
    assert server.connections == 0
    assert "Not sent in plaintext" in " ".join(result.output.split())


def test_with_every_keyserver_answering_no_key_the_report_still_goes(server, dns_replay, http_replay):
    """The other side: startpage.com as recorded, where every keyserver answers
    and none holds a key for its contacts. Plaintext is then the documented
    fallback, and refusing it would make `send` refuse every domain without a key."""
    dns_replay("startpage_com", "startpage_com_dkim_selectors")
    http_replay("startpage_com", "startpage_com_keyservers_index")

    result = _send("startpage.com", server, *NAMED)

    assert result.exit_code == 0, result.output
    assert len(server.messages) == 1
