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


class TestRecordedKeyservers:
    """Keyservers on 127.0.0.1 answering what the real ones answered (tests/replay.py)."""

    def test_pgp_mit_edu_is_no_longer_asked_by_default(self):
        """On 2026-10-09 pgp.mit.edu took 15 s to time out on each of five contacts (83 s per analysis), answered
        HTTP 500 at other moments, and when it did answer it matched search words, not addresses
        (pgp_mit_edu_pec_poste_it.json). It is not a default any more."""
        from mailradar.gpg import KEYSERVERS
        assert not any("pgp.mit.edu" in keyserver for keyserver in KEYSERVERS)

    def test_a_key_on_a_keyserver_that_does_not_verify_addresses_scores_nothing(self, http_replay):
        """keyserver.ubuntu.com lists, for security@gmail.com, a 2048-bit key uploaded in 2018 by
        'securityencyryption <security@gmail.com>' (recorded): anyone can upload a key under any address
        there, so the key is reported, not credited, and the report says why."""
        http_replay("keyservers_gmail_com")
        result = lookup_gpg("gmail.com")
        assert result.found is True
        assert result.verified is False
        assert result.score == 0
        assert result.uid == "security@gmail.com"
        assert result.fingerprint == "6902757CCE90C14EA12A5A5E44789306437E75D5"
        assert any("does not verify" in issue for issue in result.issues)

    def test_hkp_key_whose_uids_do_not_carry_the_address_is_not_a_key_for_it(self, http_replay):
        """pgp.mit.edu answers a search for postmaster@pec.poste.it with one key none of whose 72 uids
        carries that address (recorded): `check pec.poste.it` reported it as the domain's key."""
        proxy = http_replay("pgp_mit_edu_pec_poste_it")
        result = lookup_gpg_by_email("postmaster@pec.poste.it", keyservers=["https://pgp.mit.edu"])
        assert result.found is False
        assert not any("op=get" in request for request in proxy.requests)

    def test_a_keyserver_that_cannot_answer_leaves_the_check_not_verified(self, http_replay):
        """keys.openpgp.org answered HTTP 429 to every by-email lookup of github.com's contacts (recorded,
        the limit is 1/min with a burst of 50) and keyserver.ubuntu.com 404: nothing proves absence."""
        http_replay("keyservers_github_com")
        result = lookup_gpg("github.com")
        assert result.found is False
        assert "429" in result.error
        assert not any("No GPG public key" in issue for issue in result.issues)
        assert any("not verified" in issue for issue in result.issues)

    def test_a_rate_limited_keyserver_is_not_asked_again(self, http_replay):
        """HTTP 429 means the limit is spent: asking four more times spends nothing but time."""
        proxy = http_replay("keyservers_github_com")
        lookup_gpg("github.com")
        asked = [request for request in proxy.requests if request.startswith("GET https://keys.openpgp.org")]
        assert len(asked) == 1

    def test_keys_openpgp_org_is_asked_through_vks_only(self, http_replay):
        """The VKS answer is final: the HKP lookup on the same host was a second request against the same
        1/min limit, for the same answer."""
        proxy = http_replay("keyservers_gmail_com")
        lookup_gpg("gmail.com")
        asked = [request for request in proxy.requests if request.startswith("GET https://keys.openpgp.org")]
        assert asked and all("/vks/v1/by-email/" in request for request in asked)

    def test_a_key_the_keyserver_verified_is_credited(self, http_replay):
        """keys.openpgp.org lists security@mozilla.org (recorded): its owner confirmed the address."""
        http_replay("keys_openpgp_org_verified")
        result = lookup_gpg_by_email("security@mozilla.org")
        assert result.found is True
        assert result.verified is True
        assert result.score == 5
        assert result.keyserver == "https://keys.openpgp.org"
        assert result.issues == []

    def test_a_keyserver_that_does_not_answer_is_asked_once(self, http_replay):
        """A timeout costs 15 s: a keyserver that does not answer about the first address is not asked
        about the other four, and the result says the check is not verified."""
        proxy = http_replay("pgp_mit_edu_silent_first_contact", "keyservers_pec_poste_it")
        result = lookup_gpg("pec.poste.it", keyservers=["https://pgp.mit.edu", "https://keyserver.ubuntu.com"])
        asked = [request for request in proxy.requests if "pgp.mit.edu" in request and request.startswith("GET")]
        assert len(asked) == 1
        assert result.found is False
        assert "pgp.mit.edu" in result.error
