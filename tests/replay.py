"""
Real servers on 127.0.0.1 that answer with what the real services answered.

The tests talk to DNS, HTTP and SMTP the way mailradar does in production:
dnspython sends real UDP queries, httpx opens real connections, smtplib
negotiates real TLS. What answers them is local, so no test needs the public
network when it runs:

- DNSReplayServer answers each query with the response a public resolver gave
  for that name and type (tests/fixtures/dns/*.json);
- HTTPReplayProxy answers each request with the response the real service gave
  (tests/fixtures/http/*.json). httpx reaches it through HTTPS_PROXY, and it
  terminates TLS with a certificate from a CertificateAuthority that the test
  trusts through SSL_CERT_FILE;
- SMTPServer is a small SMTP server, TLS from the first byte or STARTTLS, that
  writes down every command it receives.

The role respx plays at the HTTP boundary, one level lower: here the bytes
really cross a socket. A query or request that nobody recorded is refused and
listed in `unexpected`, and the fixtures in conftest.py fail the test over it.

Every fixture file says where it comes from: `_recorded` (when, from where,
how) or `_derived` (from which recording, and what was changed).
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import re
import socket
import socketserver
import ssl
import threading
from collections.abc import Iterable
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlsplit

import dns.message
import dns.name
import dns.nameserver
import dns.rcode
import dns.rdatatype
import dns.renderer
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

FIXTURES = Path(__file__).parent / "fixtures"

# Seconds the resolver waits for an answer. A recorded answer comes back over
# loopback in a few milliseconds; a name the server keeps silent on costs this
# much, so it is short.
DNS_LIFETIME = 0.5


def _load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if "_recorded" not in data and "_derived" not in data:
        raise ValueError(f"{path.name} says neither where it was recorded nor what it is derived from")
    return data


# ─── DNS ────────────────────────────────────────────────────────────────────

def _question(message: dns.message.Message) -> str:
    """'name. TYPE' of the message's question, the name lower-cased (DNS is case-insensitive)."""
    question = message.question[0]
    return f"{question.name.to_text().lower()} {dns.rdatatype.to_text(question.rdtype)}"


def _normalised(question: str) -> str:
    name, rdtype = question.rsplit(" ", 1)
    return f"{dns.name.from_text(name).to_text().lower()} {rdtype.upper()}"


def load_dns_fixture(name: str) -> list[dns.message.Message]:
    """The responses of tests/fixtures/dns/<name>.json, each stored as its text lines."""
    data = _load(FIXTURES / "dns" / f"{name}.json")
    return [dns.message.from_text("\n".join(lines)) for lines in data["responses"]]


def recorded_txt(fixture: str, name: str) -> list[str]:
    """The TXT strings a fixture holds for `name`, joined per record as _query_txt joins them."""
    wanted = _normalised(f"{name} TXT")
    for message in load_dns_fixture(fixture):
        if _question(message) == wanted:
            return [b"".join(rdata.strings).decode("utf-8", errors="replace")
                    for rrset in message.answer for rdata in rrset]
    raise KeyError(f"{fixture} has no TXT response for {name}")


def _wire(message: dns.message.Message) -> bytes:
    """`message` in wire format exactly as the fixture spells it.

    Message.to_wire() would shuffle the records of each RRset (round-robin) and
    compress names, and its compression matches suffixes regardless of case, so
    'Hostmaster.Example.COM.' after a question for 'example.com.' would arrive
    as 'Hostmaster.example.com.'. Compression is optional (RFC 1035 §4.1.4):
    here nothing is compressed and every RRset keeps its recorded order.
    """
    renderer = dns.renderer.Renderer(message.id, message.flags, 65535)
    # Name.to_wire() compresses only into a table it is given
    renderer.compress = None  # type: ignore[assignment]
    for question in message.question:
        renderer.add_question(question.name, question.rdtype, question.rdclass)
    for section, rrsets in ((dns.renderer.ANSWER, message.answer),
                            (dns.renderer.AUTHORITY, message.authority),
                            (dns.renderer.ADDITIONAL, message.additional)):
        for rrset in rrsets:
            renderer.add_rrset(section, rrset, want_shuffle=False)
    renderer.write_header()
    return renderer.get_wire()


class DNSReplayServer:
    """A UDP DNS server on 127.0.0.1 that answers with recorded responses.

    Names in `silent` get no answer at all: that is what a timeout is, and
    there is nothing to record about it. A later response for the same
    question replaces an earlier one, so a derived fixture can follow the
    recording it changes.
    """

    def __init__(self, responses: Iterable[dns.message.Message], silent: Iterable[str] = ()):
        self.responses = {_question(message): message for message in responses}
        self.silent = {_normalised(question) for question in silent}
        self.queries: list[str] = []
        self.unexpected: list[str] = []
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(0.05)
        self.port = self._socket.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def resolver(self) -> dns.resolver.Resolver:
        """A dnspython resolver that asks this server and nobody else."""
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [dns.nameserver.Do53Nameserver("127.0.0.1", self.port)]
        resolver.timeout = resolver.lifetime = DNS_LIFETIME
        return resolver

    def answer(self, query: dns.message.Message) -> dns.message.Message | None:
        question = _question(query)
        if question in self.silent:
            return None
        recorded = self.responses.get(question)
        if recorded is None:
            self.unexpected.append(question)
            refused = dns.message.make_response(query)
            refused.set_rcode(dns.rcode.REFUSED)
            return refused
        recorded.id = query.id
        return recorded

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                wire, client = self._socket.recvfrom(65535)
            except (TimeoutError, ConnectionResetError):
                # Windows reports an earlier reply's ICMP "port unreachable"
                # on the next receive: nothing to do with this query
                continue
            except OSError:
                return
            query = dns.message.from_wire(wire)
            self.queries.append(_question(query))
            response = self.answer(query)
            if response is not None:
                self._socket.sendto(_wire(response), client)

    def close(self) -> None:
        self._stop.set()
        self._thread.join()
        self._socket.close()


# ─── TLS ────────────────────────────────────────────────────────────────────

class CertificateAuthority:
    """A CA made on the spot. Nothing trusts it unless SSL_CERT_FILE names `path`."""

    def __init__(self, directory: Path, name: str):
        self._directory = directory
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        self._ski = x509.SubjectKeyIdentifier.from_public_key(self._key.public_key())
        now = datetime.datetime.now(datetime.UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(self._name)
            .issuer_name(self._name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_key_usage(key_cert_sign=True), critical=True)
            .add_extension(self._ski, critical=False)
            .sign(self._key, hashes.SHA256())
        )
        self.path = directory / f"{name}.pem"
        self.path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._lock = threading.Lock()

    def server_context(self, host: str) -> ssl.SSLContext:
        """A server-side context with a certificate for `host` (a name or an IP), signed by this CA."""
        with self._lock:
            if host not in self._contexts:
                self._contexts[host] = self._issue(host)
            return self._contexts[host]

    def _issue(self, host: str) -> ssl.SSLContext:
        key = ec.generate_private_key(ec.SECP256R1())
        try:
            alt_name: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            alt_name = x509.DNSName(host)
        now = datetime.datetime.now(datetime.UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self._name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([alt_name]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_key_usage(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(self._ski),
                           critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        path = self._directory / f"{self.path.stem}-{re.sub(r'[^A-Za-z0-9.-]', '_', host)}.pem"
        path.write_bytes(
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
            + certificate.public_bytes(serialization.Encoding.PEM)
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(path)
        return context


def _key_usage(digital_signature: bool = False, key_cert_sign: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=key_cert_sign,
        crl_sign=key_cert_sign, encipher_only=False, decipher_only=False,
    )


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


def _read_head(reader) -> tuple[str, str] | None:
    """Method and target of an HTTP request, its headers read and dropped; None on EOF."""
    line = reader.readline().decode("latin-1").strip()
    if not line:
        return None
    while reader.readline() not in (b"\r\n", b"\n", b""):
        pass
    method, target, _ = line.split(" ", 2)
    return method, target


# ─── HTTP ───────────────────────────────────────────────────────────────────

def load_http_fixture(name: str) -> list[dict]:
    """The exchanges of tests/fixtures/http/<name>.json."""
    return _load(FIXTURES / "http" / f"{name}.json")["responses"]


class HTTPReplayProxy:
    """An HTTP proxy on 127.0.0.1 that answers with recorded responses.

    `requests` lists everything that reached it, `CONNECT host:port` lines
    included, so a test can also assert that nothing did. A recorded `error`
    is replayed by closing the connection without an answer.
    """

    def __init__(self, responses: Iterable[dict], authority: CertificateAuthority):
        self.responses = {entry["request"]: entry for entry in responses}
        self.requests: list[str] = []
        self.unexpected: list[str] = []
        self._hosts = {urlsplit(request.split(" ", 1)[1]).netloc for request in self.responses}
        self._authority = authority
        proxy = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                proxy._handle(self.request)

        self._server = _Server(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, args=(0.05,), daemon=True).start()

    def knows(self, netloc: str) -> bool:
        return netloc in self._hosts

    def respond(self, request: str) -> dict | None:
        return self.responses.get(request)

    def _handle(self, connection: socket.socket) -> None:
        head = _read_head(connection.makefile("rb", buffering=0))
        if head is None:
            return
        method, target = head
        if method == "CONNECT":
            self.requests.append(f"CONNECT {target}")
            host, _, port = target.rpartition(":")
            netloc = host if port == "443" else target
            if not self.knows(netloc):
                self.unexpected.append(f"CONNECT {target}")
                connection.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return
            connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            try:
                connection = self._authority.server_context(host.strip("[]")).wrap_socket(
                    connection, server_side=True)
            except (ssl.SSLError, OSError):
                return
            head = _read_head(connection.makefile("rb", buffering=0))
            if head is None:
                return
            method, path = head
            target = f"https://{netloc}{path}"
        request = f"{method} {target}"
        self.requests.append(request)
        entry = self.respond(request)
        if entry is None:
            self.unexpected.append(request)
            entry = {"status": 502, "body": "nothing was recorded for this request"}
        if "error" not in entry:
            connection.sendall(_http_response(entry))
        connection.close()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def _http_response(entry: dict) -> bytes:
    body = entry.get("body", "").encode("utf-8")
    status = entry["status"]
    lines = [f"HTTP/1.1 {status} {HTTPStatus(status).phrase}"]
    lines += [f"{name}: {value}" for name, value in entry.get("headers", {}).items()]
    lines += [f"Content-Length: {len(body)}", "Connection: close", "", ""]
    return "\r\n".join(lines).encode("latin-1") + body


# ─── SMTP ───────────────────────────────────────────────────────────────────

class SMTPServer:
    """An SMTP server on 127.0.0.1 that writes down every command it receives.

    mode "tls":      TLS from the first byte (SMTPS, as on port 465);
    mode "starttls": plain text until STARTTLS;
    mode "silent":   accepts the connection and never says a word.

    AUTH is offered only once TLS is up, as real servers do, and any AUTH is
    accepted: what the tests look at is whether the client ever sent one.
    """

    def __init__(self, mode: str, context: ssl.SSLContext | None = None):
        self.mode = mode
        self.context = context
        self.connections = 0
        self.commands: list[str] = []
        self.messages: list[bytes] = []
        self.handshake_errors: list[str] = []
        self._closing = threading.Event()
        self._open: list[socket.socket] = []
        server = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                server._handle(self.request)

        self._server = _Server(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, args=(0.05,), daemon=True).start()

    def _handshake(self, connection: socket.socket) -> ssl.SSLSocket | None:
        assert self.context is not None
        try:
            return self.context.wrap_socket(connection, server_side=True)
        except (ssl.SSLError, OSError) as e:
            self.handshake_errors.append(str(e))
            return None

    def _handle(self, connection: socket.socket) -> None:
        self.connections += 1
        self._open.append(connection)
        if self.mode == "silent":
            self._closing.wait()
            return
        tls = False
        if self.mode == "tls":
            wrapped = self._handshake(connection)
            if wrapped is None:
                return
            connection, tls = wrapped, True
        reader = connection.makefile("rb", buffering=0)
        connection.sendall(b"220 localhost ESMTP\r\n")
        while line := reader.readline():
            command = line.decode("utf-8", errors="replace").rstrip("\r\n")
            self.commands.append(command)
            verb = command.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                feature = "AUTH PLAIN" if tls else "STARTTLS"
                connection.sendall(f"250-localhost\r\n250 {feature}\r\n".encode())
            elif verb == "STARTTLS" and not tls:
                connection.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                wrapped = self._handshake(connection)
                if wrapped is None:
                    return
                connection, tls = wrapped, True
                reader = connection.makefile("rb", buffering=0)
            elif verb == "AUTH" and tls:
                connection.sendall(b"235 2.7.0 Authentication successful\r\n")
            elif verb in ("MAIL", "RCPT"):
                connection.sendall(b"250 2.1.0 OK\r\n")
            elif verb == "DATA":
                connection.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                data = b""
                while (chunk := reader.readline()) not in (b".\r\n", b""):
                    data += chunk
                self.messages.append(data)
                connection.sendall(b"250 2.0.0 OK\r\n")
            elif verb == "QUIT":
                connection.sendall(b"221 2.0.0 Bye\r\n")
                return
            else:
                connection.sendall(b"502 5.5.2 Command not recognised\r\n")

    def close(self) -> None:
        self._closing.set()
        for connection in self._open:
            connection.close()
        self._server.shutdown()
        self._server.server_close()
