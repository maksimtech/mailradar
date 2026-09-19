"""Tests for the local cache of EU law provisions."""
import json
from pathlib import Path

import pytest

from mailradar.law_cache import LawCache, default_cache_path
from mailradar.law_fetcher import Provision

DAY1 = "2026-09-19T14:00:00Z"
DAY2 = "2026-10-01T09:30:00Z"
GDPR = "32016R0679"
EPRIVACY = "02002L0058-20091219"


def _p(article, text, fetched_at=DAY1, celex=GDPR):
    return Provision.from_text(article, text, fetched_at, celex)


def test_tests_never_use_the_real_home():
    # conftest points MAILRADAR_HOME at a temporary folder for every test
    real = Path.home() / ".mailradar"
    assert real not in default_cache_path().parents


def test_default_path_is_under_home_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MAILRADAR_HOME", str(tmp_path / "home"))
    assert default_cache_path() == tmp_path / "home" / "law_cache.json"


def test_default_path_without_env(monkeypatch):
    monkeypatch.delenv("MAILRADAR_HOME", raising=False)
    assert default_cache_path() == Path.home() / ".mailradar" / "law_cache.json"


def test_missing_file_is_empty(tmp_path):
    assert LawCache(tmp_path / "law_cache.json").load() == {}


def test_first_update_stores_everything(tmp_path):
    path = tmp_path / "sub" / "law_cache.json"
    cache = LawCache(path)
    p = _p("32(1)(a)", "a) testo;")
    provisions, changed = cache.update({p.key: p}, checked_at=DAY1)

    assert changed == {}
    assert provisions[(GDPR, "32(1)(a)")].text == "a) testo;"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["checked_at"] == DAY1
    assert data["entries"] == [p.to_dict()]
    assert cache.load() == provisions


def test_same_article_number_in_two_acts(tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    gdpr = _p("5(3)", "GDPR 5(3)")
    eprivacy = _p("5(3)", "ePrivacy 5(3)", celex=EPRIVACY)
    cache.update({gdpr.key: gdpr, eprivacy.key: eprivacy}, checked_at=DAY1)

    loaded = cache.load()
    assert loaded[(GDPR, "5(3)")].text == "GDPR 5(3)"
    assert loaded[(EPRIVACY, "5(3)")].text == "ePrivacy 5(3)"


def test_same_text_keeps_the_original_version(tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    cache.update({(GDPR, "32"): _p("32", "testo")}, checked_at=DAY1)

    provisions, changed = cache.update({(GDPR, "32"): _p("32", "testo", DAY2)}, checked_at=DAY2)

    assert changed == {}
    # The version date is when this text was first fetched
    assert provisions[(GDPR, "32")].fetched_at == DAY1
    assert json.loads(cache.path.read_text(encoding="utf-8"))["checked_at"] == DAY2


def test_changed_text_replaces_entry_and_reports_old_hash(tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    old = _p("32", "testo")
    cache.update({old.key: old}, checked_at=DAY1)

    provisions, changed = cache.update({old.key: _p("32", "testo modificato", DAY2)}, checked_at=DAY2)

    assert changed == {(GDPR, "32"): old.sha256}
    assert provisions[(GDPR, "32")].fetched_at == DAY2
    assert cache.load()[(GDPR, "32")].text == "testo modificato"


def test_entries_not_fetched_again_are_kept(tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    cache.update({(GDPR, "25"): _p("25", "venticinque"), (GDPR, "32"): _p("32", "trentadue")}, checked_at=DAY1)

    provisions, _ = cache.update({(GDPR, "32"): _p("32", "trentadue", DAY2)}, checked_at=DAY2)

    assert set(provisions) == {(GDPR, "25"), (GDPR, "32")}


def test_corrupt_file_is_empty(tmp_path):
    path = tmp_path / "law_cache.json"
    path.write_text("{not json", encoding="utf-8")
    assert LawCache(path).load() == {}


def test_unexpected_structure_is_empty(tmp_path):
    path = tmp_path / "law_cache.json"
    path.write_text('["a", "b"]', encoding="utf-8")
    assert LawCache(path).load() == {}


def test_entry_whose_hash_does_not_match_its_text_is_dropped(tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    cache.update({(GDPR, "25"): _p("25", "venticinque"), (GDPR, "32"): _p("32", "trentadue")}, checked_at=DAY1)

    data = json.loads(cache.path.read_text(encoding="utf-8"))
    for entry in data["entries"]:
        if entry["article"] == "32":
            entry["text"] = "trentadue, modificato a mano"
    cache.path.write_text(json.dumps(data), encoding="utf-8")

    assert set(cache.load()) == {(GDPR, "25")}


def test_no_temporary_file_left(tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    cache.update({(GDPR, "32"): _p("32", "trentadue")}, checked_at=DAY1)
    assert [p.name for p in tmp_path.iterdir()] == ["law_cache.json"]


def test_failed_write_leaves_no_temporary_file(tmp_path, monkeypatch):
    import os

    cache = LawCache(tmp_path / "law_cache.json")

    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError):
        cache.update({(GDPR, "32"): _p("32", "trentadue")}, checked_at=DAY1)
    assert list(tmp_path.iterdir()) == []
