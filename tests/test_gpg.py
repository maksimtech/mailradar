"""Tests for GPG keyserver lookup."""
import sys
from unittest.mock import MagicMock, patch

import pytest

from mailradar.gpg import lookup_gpg, lookup_gpg_by_email


class TestLookupGPG:

    @pytest.mark.skipif(
        sys.version_info >= (3, 14),
        reason="SSL timeout on Python 3.14"
    )
    def test_domain_without_tld_returns_not_found(self):
        result = lookup_gpg("nodomain")
        assert result.found is False
        assert len(result.issues) > 0

    def test_gpg_found_on_keyserver(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----"

        with patch('mailradar.gpg.httpx.Client') as mock_client:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.get = MagicMock(return_value=mock_resp)
            mock_client.return_value = mock_ctx

            result = lookup_gpg_by_email("security@example.com")

        assert result.found is True

    def test_gpg_not_found(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "Not found"

        with patch('mailradar.gpg.httpx.Client') as mock_client:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.get = MagicMock(return_value=mock_resp)
            mock_client.return_value = mock_ctx

            result = lookup_gpg_by_email("nobody@example.com")

        assert result.found is False

    def test_gpg_timeout_returns_not_found(self):
        import httpx
        with patch('mailradar.gpg.httpx.Client') as mock_client:
            mock_ctx = MagicMock()
            mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
            mock_ctx.__exit__ = MagicMock(return_value=False)
            mock_ctx.get = MagicMock(side_effect=httpx.TimeoutException("timeout"))
            mock_client.return_value = mock_ctx

            result = lookup_gpg_by_email("test@example.com")

        assert result.found is False
