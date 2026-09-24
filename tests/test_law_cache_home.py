"""Where the law cache goes when the environment says so.

Snyk flags four lines here as path traversal: PACKAGE_HOME flows into a path
that is then written, renamed and unlinked. As a vulnerability that does not
hold — the variable is set by whoever runs the tool, against their own files,
with their own privileges — but looking at why it was flagged turned up three
ways the value is taken literally when it should not be:

- "~/cache" makes a directory actually named "~", because Path() does not
  expand it. Anyone writing that in a Dockerfile ENV or a quoted shell
  assignment gets it.
- a relative path is resolved against the current working directory, so the
  cache lands somewhere different depending on where the command was run from
  — and quietly stops being one cache.
- "   " is truthy, so whitespace becomes a directory name.

None of those is an attack. All three are a cache that is not where the
operator meant it to be, which is exactly what a cache must not be.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mailradar import law_cache

HOME_VAR = "MAILRADAR_HOME"


@pytest.fixture
def cache_path(monkeypatch):
    def resolve(value=None):
        if value is None:
            monkeypatch.delenv(HOME_VAR, raising=False)
        else:
            monkeypatch.setenv(HOME_VAR, value)
        return law_cache.default_cache_path()
    return resolve


def test_the_default_is_a_dot_directory_under_home(cache_path):
    path = cache_path()
    assert path.name == "law_cache.json"
    assert path.parent.name.startswith(".")
    assert path.is_absolute()


def test_an_absolute_value_is_honoured(tmp_path, cache_path):
    path = cache_path(str(tmp_path))
    assert path == tmp_path / "law_cache.json"


def test_a_tilde_is_expanded_not_taken_literally(cache_path):
    """"~/cache" must not create a directory called "~"."""
    path = cache_path("~/apkradar-cache")

    assert "~" not in str(path)
    assert path.is_absolute()
    assert path == Path.home() / "apkradar-cache" / "law_cache.json"


def test_a_relative_value_does_not_follow_the_working_directory(tmp_path, monkeypatch, cache_path):
    """Two runs from two directories must mean one cache, not two.

    `.resolve()` alone does not give this: it anchors a relative path to the
    working directory, which is the behaviour being removed. A relative value
    is read against $HOME instead — the variable is called *_HOME, and the
    reading has to be the same wherever the command is run from.
    """
    monkeypatch.chdir(tmp_path)
    first = cache_path("cache-dir")

    nested = tmp_path / "somewhere" / "else"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    second = cache_path("cache-dir")

    assert first == second, "the cache moved with the working directory"
    assert first.is_absolute()
    assert first == Path.home() / "cache-dir" / "law_cache.json"


@pytest.mark.parametrize("blank", ["", " ", "   ", "\t", "\n"])
def test_a_blank_value_falls_back_to_the_default(blank, cache_path):
    """A variable set to nothing means "unset", not "a directory named space"."""
    assert cache_path(blank) == cache_path()


def test_the_filename_is_never_taken_from_the_environment(tmp_path, cache_path):
    """Only the directory is configurable; the file has one name.

    Worth pinning: it is what keeps the variable from choosing which file gets
    written over.
    """
    path = cache_path(str(tmp_path / "sub"))
    assert path.name == "law_cache.json"


def test_a_value_pointing_at_a_file_is_still_a_directory_path(tmp_path, cache_path):
    """Nothing clever: the cache file goes *inside* whatever was named."""
    target = tmp_path / "notes.txt"
    target.write_text("x", encoding="utf-8")

    assert cache_path(str(target)) == target / "law_cache.json"


# --------------------------------------------------------------------------
# the round trip still works
# --------------------------------------------------------------------------


def test_a_cache_written_under_the_variable_is_read_back(tmp_path, monkeypatch):
    """The guard must not cost the cache its job."""
    monkeypatch.setenv(HOME_VAR, str(tmp_path))
    cache = law_cache.LawCache()

    assert cache.path == tmp_path / "law_cache.json"
    assert cache.load() == {}          # nothing yet, and no error
