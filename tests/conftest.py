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


# ─── Recorded DNS, HTTP and SMTP on 127.0.0.1 (tests/replay.py) ─────────────


@pytest.fixture(scope="session")
def trusted_ca(tmp_path_factory):
    """The CA the replay servers sign with; trusted only where SSL_CERT_FILE names it."""
    from tests.replay import CertificateAuthority

    return CertificateAuthority(tmp_path_factory.mktemp("trusted-ca"), "mailradar-test-ca")


@pytest.fixture
def dns_replay():
    """dns_replay("fixture", ..., silent=["name TYPE", ...]) — dnspython asks a
    DNSReplayServer serving those recordings, and nobody else, until the test ends."""
    import dns.resolver

    from tests.replay import DNSReplayServer, load_dns_fixture

    servers = []
    saved = dns.resolver.default_resolver

    def start(*fixtures: str, silent=()):
        server = DNSReplayServer([m for f in fixtures for m in load_dns_fixture(f)], silent)
        servers.append(server)
        # dnspython's documented way to choose the resolver that
        # dns.resolver.resolve() uses: a real one, pointed at the local server
        dns.resolver.default_resolver = server.resolver()
        return server

    yield start
    dns.resolver.default_resolver = saved
    for server in servers:
        server.close()
    unexpected = [question for server in servers for question in server.unexpected]
    if unexpected:
        pytest.fail(f"DNS queries nobody recorded: {unexpected}")


@pytest.fixture
def http_replay(monkeypatch, trusted_ca):
    """http_replay("fixture", ...) — httpx goes through an HTTPReplayProxy serving
    those recordings, and trusts its certificates, until the test ends."""
    from tests.replay import HTTPReplayProxy, load_http_fixture

    proxies = []

    def start(*fixtures: str):
        proxy = HTTPReplayProxy([e for f in fixtures for e in load_http_fixture(f)], trusted_ca)
        proxies.append(proxy)
        for variable in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
            monkeypatch.setenv(variable, proxy.url)
        for variable in ("ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_DIR"):
            monkeypatch.delenv(variable, raising=False)
        monkeypatch.setenv("SSL_CERT_FILE", str(trusted_ca.path))
        return proxy

    yield start
    for proxy in proxies:
        proxy.close()
    unexpected = [request for proxy in proxies for request in proxy.unexpected]
    if unexpected:
        pytest.fail(f"HTTP requests nobody recorded: {unexpected}")


@pytest.fixture
def smtp_server():
    """smtp_server(mode, context=None) — a real SMTPServer on 127.0.0.1, closed when the test ends."""
    from tests.replay import SMTPServer

    servers = []

    def start(mode: str, context=None):
        server = SMTPServer(mode, context)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()
