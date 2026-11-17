"""
MailRadar — Email sender with optional GPG encryption.
"""

import contextlib
import getpass
import smtplib
import ssl
import subprocess
import tempfile
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from urllib.parse import urlsplit

# Seconds before a silent SMTP server is given up on: without it `send` could
# wait for ever on a connection that never answers.
SMTP_TIMEOUT = 30


@dataclass
class SMTPConfig:
    host: str
    port: int
    username: str
    password: str
    from_email: str
    from_name: str = "MailRadar Security Audit"
    use_tls: bool = True


@dataclass
class SendResult:
    sent: bool = False
    encrypted: bool = False
    recipient: str = ""
    # "gpg-encrypted", "manual-gpg", "gpg-failed", "gpg-unverified", "sign-failed", "plaintext",
    # "smtp-failed", "manual"
    method: str = ""
    message: str = ""
    # What the SMTP server answered, or what happened on the way, when delivery was tried and failed
    error: str = ""


def _without_subject_line(text: str) -> str:
    """`text` without the "Subject: …" / "Oggetto: …" line the letter opens with, and the blank line after it."""
    first, newline, rest = text.partition("\n")
    if newline and first.startswith(("Subject:", "Oggetto:")):
        return rest.lstrip("\n")
    return text


def _normalised_fingerprint(fingerprint: str) -> str:
    """'3bb5 47f4 …', '0x3BB547F4…' and '3BB547F4…' are the same fingerprint."""
    compact = "".join(fingerprint.split()).upper()
    return compact.removeprefix("0X")


def unconfirmed_key(gpg_result, fingerprint: str | None) -> str:
    """Why the key in `gpg_result` may not be encrypted to; "" when it may.

    A key keys.openpgp.org lists (VKS, or WKD) was published by the address's
    owner. One from keyserver.ubuntu.com may have been uploaded by anybody, under
    any name: encrypting to it can hand the report to whoever uploaded it. It is
    used only when the user has confirmed its fingerprint with the domain and
    passes it, and the fingerprint matches the key found.
    """
    if not gpg_result.found or not gpg_result.uid:
        # A fingerprint given says encryption is expected: no key is no reason for plaintext
        return (f"--gpg-fingerprint {_normalised_fingerprint(fingerprint)} was given, but no key was found "
                "for the domain's contacts" if fingerprint is not None else "")
    found = _normalised_fingerprint(gpg_result.fingerprint or "")
    if fingerprint is not None and found and _normalised_fingerprint(fingerprint) != found:
        return (f"the fingerprint given, {_normalised_fingerprint(fingerprint)}, does not match the key found for "
                f"{gpg_result.uid}, {found}")
    if gpg_result.verified or fingerprint is not None:
        return ""
    host = urlsplit(gpg_result.keyserver or "").hostname or gpg_result.keyserver or "the keyserver"
    reason = (f"the GPG key for {gpg_result.uid} comes from {host}, which does not verify addresses — anyone "
              f"can publish a key there under any name. Fingerprint: {found or 'unknown'}")
    if getattr(gpg_result, "unanswered", ""):
        reason += f". Not answered: {gpg_result.unanswered}, so a verified key may also exist"
    return reason


def _encrypt_with_gpg(
    text: str,
    recipient_email: str,
    public_key: str | None = None,
) -> str | None:
    """
    Encrypt text with recipient's GPG public key.

    If `public_key` (armored, as fetched from a keyserver) is given, it is
    imported into a throwaway keyring so the user's keyring is untouched and
    the key does not need to be trusted locally. Otherwise the user's keyring
    is used.
    """
    try:
        with tempfile.TemporaryDirectory(prefix="mailradar-gpg-", ignore_cleanup_errors=True) as homedir:
            # Local keys only. gpg's default `auto-key-locate local,wkd` looked
            # an unusable key's address up through WKD (openpgpkey.<domain>),
            # which started a dirmngr that outlived the throwaway homedir
            base = ["gpg", "--batch", "--yes", "--auto-key-locate", "clear,local", "--no-auto-key-retrieve"]
            if not public_key:
                return _gpg_encrypt(base, text, recipient_email)
            base += ["--homedir", homedir]
            try:
                imported = subprocess.run(
                    base + ["--import"],
                    input=public_key.encode(),
                    capture_output=True,
                    timeout=30,
                )
                if imported.returncode != 0:
                    return None
                return _gpg_encrypt(base, text, recipient_email)
            finally:
                # Whatever gpg started for this homedir (gpg-agent, dirmngr)
                # goes with it
                _stop_gpg_daemons(homedir)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _gpg_encrypt(base: list[str], text: str, recipient: str) -> str | None:
    result = subprocess.run(
        base + [
            # A key just fetched: without this, gpg --batch refuses it
            "--trust-model", "always",
            "--armor",
            "--encrypt",
            "--recipient", recipient,
        ],
        input=text.encode(),
        capture_output=True,
        timeout=30,
    )
    if result.returncode == 0:
        return result.stdout.decode()
    return None


def _stop_gpg_daemons(homedir: str) -> None:
    """`gpgconf --kill all` for `homedir`; a gpgconf that is missing or hangs changes nothing."""
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(["gpgconf", "--homedir", homedir, "--kill", "all"], capture_output=True, timeout=30)

def _sign_with_gpg(text: str, sender_email: str, passphrase: str | None = None) -> str | None:
    """Sign text with sender's GPG private key; the passphrase is asked here when not given.

    `send` asks for it before its spinner starts: getpass under a Rich status
    has its prompt redrawn over.
    """
    try:
        if passphrase is None:
            passphrase = getpass.getpass(f"GPG passphrase for {sender_email}: ")
        cmd = [
            "gpg",
            "--batch",
            "--yes",
            "--armor",
            "--clearsign",
            "--local-user", sender_email,
            "--passphrase-fd", "0",
            "--pinentry-mode", "loopback",
        ]
        result = subprocess.run(
            cmd,
            input=f"{passphrase}\n{text}".encode(),
            capture_output=True,
            timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.decode()
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, KeyboardInterrupt):
        return None

def _send_smtp(
    config: SMTPConfig,
    to_email: str,
    subject: str,
    body: str,
    encrypted: bool = False,
) -> bool:
    """Send email via SMTP; False, whatever the reason, when it was not delivered."""
    try:
        _deliver(config, to_email, subject, body, encrypted)
        return True
    except Exception:
        return False


class SMTPDeliveryError(Exception):
    """The message was not delivered. `recipient` is True when the server refused the address, and only then."""

    def __init__(self, message: str, recipient: bool = False):
        super().__init__(message)
        self.recipient = recipient


def _describe(error: Exception) -> str:
    """What the server said, '535 5.7.8 Authentication credentials invalid', or what happened on the way."""
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        return "; ".join(f"{address}: {code} {reply.decode(errors='replace')}"
                         for address, (code, reply) in error.recipients.items())
    if isinstance(error, smtplib.SMTPResponseException):
        reply = error.smtp_error.decode(errors="replace") if isinstance(error.smtp_error, bytes) \
            else str(error.smtp_error)
        return f"{error.smtp_code} {reply}"
    return str(error) or type(error).__name__


def _deliver(
    config: SMTPConfig,
    to_email: str,
    subject: str,
    body: str,
    encrypted: bool = False,
) -> None:
    """Deliver one message, or raise SMTPDeliveryError saying why not.

    Only a refused recipient is something the next address can fix. A wrong
    password, a certificate that does not verify, a server that cannot be
    reached are the same for every address: trying five of them was five
    logins on five connections, which is how an account gets locked.
    """
    msg = MIMEMultipart()
    # formataddr quotes the name: "[NOME] <a@b>" built by hand parsed to no
    # address at all ([ and ] are RFC 5322 specials) and "Rossi, Mario <a@b>"
    # to "Rossi", and smtplib took the envelope sender from that — MAIL
    # FROM:<>, the bounce reverse-path. Date is required (RFC 5322 §3.6),
    # and a message without a Message-ID reads as spam.
    msg["From"] = formataddr((config.from_name, config.from_email))
    msg["To"] = to_email
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=config.from_email.rpartition("@")[2])
    msg.attach(MIMEText(body, "plain", "utf-8"))
    if encrypted:
        msg["X-MailRadar-Encrypted"] = "GPG"

    # Without a context smtplib verifies neither the certificate nor the
    # host name (CERT_NONE): anyone on the path could present any
    # certificate and read the password handed to login().
    context = ssl.create_default_context()
    try:
        server: smtplib.SMTP = (
            smtplib.SMTP_SSL(config.host, config.port, context=context, timeout=SMTP_TIMEOUT)
            if config.use_tls else smtplib.SMTP(config.host, config.port, timeout=SMTP_TIMEOUT)
        )
    except (OSError, smtplib.SMTPException) as e:
        raise SMTPDeliveryError(f"{config.host}:{config.port}: {_describe(e)}") from e
    try:
        if not config.use_tls:
            server.starttls(context=context)
        server.login(config.username, config.password)
        # The envelope stated, not inferred from the headers.
        server.send_message(msg, from_addr=config.from_email, to_addrs=[to_email])
    except smtplib.SMTPRecipientsRefused as e:
        server.close()
        raise SMTPDeliveryError(_describe(e), recipient=True) from e
    except (OSError, smtplib.SMTPException) as e:
        server.close()
        raise SMTPDeliveryError(_describe(e)) from e
    # 250 to DATA: the message is the server's now. SMTP.__exit__ raised when
    # QUIT got anything but 221, and the report was sent again to the next
    # address, five times, with the user told it had not gone.
    try:
        server.quit()
    except (OSError, smtplib.SMTPException):
        server.close()


def send_report(
    domain: str,
    report_text: str,
    gpg_result,
    config: SMTPConfig | None = None,
    lang: str = "it",
    sign: bool = False,
    sign_email: str | None = None,
    fingerprint: str | None = None,
    sign_passphrase: str | None = None,
) -> SendResult:
    """
    Smart send logic:
    1. If GPG key found → encrypt and send to key owner address; a key from a
       keyserver that does not verify addresses only with `fingerprint`, the
       user's confirmation of it
    2. If no GPG key but SMTP configured → send plaintext
    3. If no SMTP → return manual template
    """
    result = SendResult()

    refusal = unconfirmed_key(gpg_result, fingerprint)
    if refusal:
        # Not plaintext instead, and not the encrypted text for a manual send:
        # either would go to, or be readable by, whoever uploaded the key
        result.recipient = gpg_result.uid
        result.method = "gpg-unverified"
        result.message = refusal
        return result

    subject_it = f"Analisi postura email — {domain} — MailRadar Report"
    subject_en = f"Email security posture analysis — {domain} — MailRadar Report"
    # The letter's own "Subject: …" line is for whoever copies it by hand:
    # mailed, it repeated the Subject header as the first line of the body
    report_text = _without_subject_line(report_text)
    if sign:
        # Asked for and not obtained, a signature is not silently left out:
        # the report would go out unsigned to someone told to expect one
        signed = _sign_with_gpg(report_text, sign_email, sign_passphrase) if sign_email else None
        if not signed:
            result.method = "sign-failed"
            result.message = (
                f"the report is not signed — gpg could not sign it with the key of {sign_email} "
                "(wrong passphrase, or no secret key for that address in your keyring)" if sign_email
                else "the report is not signed — --sign needs the address whose key signs it (--from)"
            )
            return result
        report_text = signed
    subject = subject_it if lang == "it" else subject_en

    # Case 1: GPG key found
    if gpg_result.found and gpg_result.uid:
        # To the confirmed fingerprint when there is one: gpg then refuses any
        # key in the keyserver's answer that is not that one
        encrypted_text = _encrypt_with_gpg(
            report_text,
            _normalised_fingerprint(fingerprint) if fingerprint else gpg_result.uid,
            getattr(gpg_result, "raw_key", "") or None,
        )

        if encrypted_text and config:
            try:
                _deliver(config, gpg_result.uid, subject, encrypted_text, encrypted=True)
            except SMTPDeliveryError as e:
                # Said, not lost: the CLI told the user "no SMTP configured"
                result.error = str(e)
            else:
                result.sent = True
                result.encrypted = True
                result.recipient = gpg_result.uid
                result.method = "gpg-encrypted"
                result.message = f"✅ Report sent GPG-encrypted to {gpg_result.uid}"
                return result

        # SMTP failed or not configured — return encrypted text for manual send
        if encrypted_text:
            result.sent = False
            result.encrypted = True
            result.recipient = gpg_result.uid
            result.method = "manual-gpg"
            result.message = encrypted_text
            return result

        # A key exists but encryption failed — never silently downgrade to plaintext
        result.sent = False
        result.encrypted = False
        result.recipient = gpg_result.uid
        result.method = "gpg-failed"
        result.message = (
            f"GPG key found for {gpg_result.uid} but encryption failed — "
            "report NOT sent"
        )
        return result

    # Case 2: No GPG — try plaintext SMTP
    if config:
        # Try common security contacts
        contacts = [
            f"security@{domain}",
            f"dpo@{domain}",
            f"privacy@{domain}",
            f"admin@{domain}",
            f"postmaster@{domain}",
        ]

        refused = []
        for contact in contacts:
            try:
                _deliver(config, contact, subject, report_text)
            except SMTPDeliveryError as e:
                if e.recipient:
                    # The one failure the next address can fix
                    refused.append(str(e))
                    continue
                result.recipient = contact
                result.method = "smtp-failed"
                result.error = str(e)
                result.message = report_text
                return result
            result.sent = True
            result.encrypted = False
            result.recipient = contact
            result.method = "plaintext"
            result.message = f"✅ Report sent in plaintext to {contact}"
            return result
        result.recipient = " / ".join(contacts)
        result.method = "smtp-failed"
        result.error = "every address was refused: " + "; ".join(refused)
        result.message = report_text
        return result

    # Case 3: Manual — return template for copy-paste
    result.sent = False
    result.encrypted = False
    result.method = "manual"
    result.recipient = f"dpo@{domain} / security@{domain} / postmaster@{domain}"
    result.message = report_text
    return result
