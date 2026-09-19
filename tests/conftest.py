"""Shared test setup."""
import pytest


@pytest.fixture(autouse=True)
def _isolate_law_checker(tmp_path, monkeypatch):
    """No test may reach EUR-Lex or write to ~/.mailradar: the law cache goes
    to a temporary folder and every download fails."""
    from mailradar import law_fetcher

    monkeypatch.setenv("MAILRADAR_HOME", str(tmp_path / "mailradar-home"))

    def no_network(*args, **kwargs):
        raise law_fetcher.LawFetchError("network disabled in tests")

    monkeypatch.setattr(law_fetcher, "fetch_html", no_network)
