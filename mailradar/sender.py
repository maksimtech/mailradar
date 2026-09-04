"""
MailRadar — Email sender with optional GPG encryption.
"""

import smtplib
import subprocess
import tempfile
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


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
    method: str = ""  # "gpg-encrypted", "plaintext", "manual"
    message: str = ""


def _encrypt_with_gpg(text: str, recipient_email: str) -> Optional[str]:
    """Encrypt text with recipient's GPG public key."""
    try:
        result = subprocess.run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--armor",
                "--encrypt",
                "--recipient", recipient_email,
                "--trust-model", "always",
            ],
            input=text.encode(),
            capture_output=True,
            timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.decode()
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _send_smtp(
    config: SMTPConfig,
    to_email: str,
    subject: str,
    body: str,
    encrypted: bool = False,
) -> bool:
    """Send email via SMTP."""
    try:
        msg = MIMEMultipart()
        msg["From"] = f"{config.from_name} <{config.from_email}>"
        msg["To"] = to_email
        msg["Subject"] = subject

        if encrypted:
            msg.attach(MIMEText(body, "plain", "utf-8"))
            msg["X-MailRadar-Encrypted"] = "GPG"
        else:
            msg.attach(MIMEText(body, "plain", "utf-8"))

        if config.use_tls:
            with smtplib.SMTP_SSL(config.host, config.port) as server:
                server.login(config.username, config.password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(config.host, config.port) as server:
                server.starttls()
                server.login(config.username, config.password)
                server.send_message(msg)

        return True
    except Exception as e:
        print(f"SMTP error: {e}")
        return False


def send_report(
    domain: str,
    report_text: str,
    gpg_result,
    config: Optional[SMTPConfig] = None,
    lang: str = "it",
) -> SendResult:
    """
    Smart send logic:
    1. If GPG key found → encrypt and send to key owner address
    2. If no GPG key but SMTP configured → send plaintext
    3. If no SMTP → return manual template
    """
    result = SendResult()

    subject_it = f"Analisi postura email — {domain} — MailRadar Report"
    subject_en = f"Email security posture analysis — {domain} — MailRadar Report"
    subject = subject_it if lang == "it" else subject_en

    # Case 1: GPG key found
    if gpg_result.found and gpg_result.uid:
        encrypted_text = _encrypt_with_gpg(report_text, gpg_result.uid)

        if encrypted_text and config:
            sent = _send_smtp(config, gpg_result.uid, subject, encrypted_text, encrypted=True)
            if sent:
                result.sent = True
                result.encrypted = True
                result.recipient = gpg_result.uid
                result.method = "gpg-encrypted"
                result.message = f"✅ Report sent GPG-encrypted to {gpg_result.uid}"
                return result

        # GPG encryption failed or no SMTP — return encrypted text for manual send
        if encrypted_text:
            result.sent = False
            result.encrypted = True
            result.recipient = gpg_result.uid
            result.method = "manual-gpg"
            result.message = encrypted_text
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

        for contact in contacts:
            sent = _send_smtp(config, contact, subject, report_text)
            if sent:
                result.sent = True
                result.encrypted = False
                result.recipient = contact
                result.method = "plaintext"
                result.message = f"✅ Report sent in plaintext to {contact}"
                return result

    # Case 3: Manual — return template for copy-paste
    result.sent = False
    result.encrypted = False
    result.method = "manual"
    result.recipient = f"dpo@{domain} / security@{domain} / postmaster@{domain}"
    result.message = report_text
    return result
