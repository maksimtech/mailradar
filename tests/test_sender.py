"""
Tests for MailRadar sender module.
Uses mocks to avoid real SMTP connections and GPG interactions.
"""
import pytest
from unittest.mock import patch, MagicMock
from mailradar.sender import (
    _encrypt_with_gpg,
    _sign_with_gpg,
    _send_smtp,
    send_report,
    SMTPConfig,
    SendResult,
)
from mailradar.checker import GPGResult


# ─── Fixtures ───────────────────────────────────────────────────────────────

def make_smtp_config():
    return SMTPConfig(
        host="mail.infomaniak.com",
        port=465,
        username="security@maksimtech.com",
        password="test_password",
        from_email="security@maksimtech.com",
        from_name="MailRadar Test",
    )


def make_gpg_result(found=False, uid=None):
    result = GPGResult()
    result.found = found
    result.uid = uid
    return result


# ─── _encrypt_with_gpg ──────────────────────────────────────────────────────

def test_encrypt_with_gpg_success():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"-----BEGIN PGP MESSAGE-----\ntest\n-----END PGP MESSAGE-----\n"
        )
        result = _encrypt_with_gpg("test report", "test@example.com")
        assert result is not None
        assert "PGP MESSAGE" in result


def test_encrypt_with_gpg_failure():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout=b"")
        result = _encrypt_with_gpg("test report", "test@example.com")
        assert result is None


def test_encrypt_with_gpg_timeout():
    import subprocess
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("gpg", 30)):
        result = _encrypt_with_gpg("test report", "test@example.com")
        assert result is None


def test_encrypt_with_gpg_not_found():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = _encrypt_with_gpg("test report", "test@example.com")
        assert result is None


# ─── _sign_with_gpg ─────────────────────────────────────────────────────────

def test_sign_with_gpg_success():
    with patch("getpass.getpass", return_value="test_passphrase"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"-----BEGIN PGP SIGNED MESSAGE-----\ntest\n-----END PGP SIGNATURE-----\n"
        )
        result = _sign_with_gpg("test report", "security@maksimtech.com")
        assert result is not None
        assert "PGP SIGNED MESSAGE" in result


def test_sign_with_gpg_failure():
    with patch("getpass.getpass", return_value="wrong_passphrase"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=2, stdout=b"")
        result = _sign_with_gpg("test report", "security@maksimtech.com")
        assert result is None


def test_sign_with_gpg_keyboard_interrupt():
    with patch("getpass.getpass", side_effect=KeyboardInterrupt):
        result = _sign_with_gpg("test report", "security@maksimtech.com")
        assert result is None


# ─── _send_smtp ─────────────────────────────────────────────────────────────

def test_send_smtp_ssl_success():
    with patch("smtplib.SMTP_SSL") as mock_smtp:
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp.return_value.__exit__ = MagicMock(return_value=False)
        config = make_smtp_config()
        result = _send_smtp(config, "test@example.com", "Test Subject", "Test body")
        assert result is True


def test_send_smtp_failure():
    with patch("smtplib.SMTP_SSL", side_effect=Exception("Connection failed")), \
         patch("smtplib.SMTP", side_effect=Exception("Connection failed")):
        config = make_smtp_config()
        result = _send_smtp(config, "test@example.com", "Test Subject", "Test body")
        assert result is False


# ─── send_report ────────────────────────────────────────────────────────────

def test_send_report_no_gpg_no_smtp():
    gpg = make_gpg_result(found=False)
    result = send_report(
        domain="example.com",
        report_text="Test report",
        gpg_result=gpg,
        config=None,
    )
    assert result.sent is False
    assert result.method == "manual"


def test_send_report_plaintext_smtp():
    gpg = make_gpg_result(found=False)
    config = make_smtp_config()
    with patch("mailradar.sender._send_smtp", return_value=True):
        result = send_report(
            domain="example.com",
            report_text="Test report",
            gpg_result=gpg,
            config=config,
        )
        assert result.sent is True
        assert result.method == "plaintext"


def test_send_report_gpg_encrypted():
    gpg = make_gpg_result(found=True, uid="test@example.com")
    config = make_smtp_config()
    with patch("mailradar.sender._encrypt_with_gpg", return_value="ENCRYPTED"), \
         patch("mailradar.sender._send_smtp", return_value=True):
        result = send_report(
            domain="example.com",
            report_text="Test report",
            gpg_result=gpg,
            config=config,
        )
        assert result.sent is True
        assert result.method == "gpg-encrypted"
        assert result.encrypted is True


def test_send_report_with_sign():
    gpg = make_gpg_result(found=False)
    config = make_smtp_config()
    with patch("mailradar.sender._sign_with_gpg", return_value="SIGNED REPORT"), \
         patch("mailradar.sender._send_smtp", return_value=True):
        result = send_report(
            domain="example.com",
            report_text="Test report",
            gpg_result=gpg,
            config=config,
            sign=True,
            sign_email="security@maksimtech.com",
        )
        assert result.sent is True
