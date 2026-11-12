"""The live benchmark must probe the protocol the port actually speaks.

Measured 2026-11-10: the phone lab's real MDM on 8443 and real adbd on 5555
were both scored `unknown`. The benchmark sent a cleartext HTTP request to a
TLS listener and a raw (unframed) CNXN header to adbd, then blamed the
services. These tests pin the two wire-level fixes without needing Docker.
"""
import struct

from scripts import live_benchmark as lb


class _FakeSocket:
    def __init__(self, reply: bytes = b""):
        self.reply = reply
        self.sent = b""
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, count: int) -> bytes:
        data, self.reply = self.reply[:count], self.reply[count:]
        return data

    def settimeout(self, _seconds: float) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class _FakeTlsContext:
    def __init__(self):
        self.check_hostname = True
        self.verify_mode = None
        self.wrapped = []

    def wrap_socket(self, sock, server_hostname=None):
        self.wrapped.append(server_hostname)
        return sock


def test_8443_is_an_https_port_not_a_cleartext_http_port(monkeypatch):
    context = _FakeTlsContext()
    monkeypatch.setattr(
        lb.socket, "create_connection",
        lambda *a, **k: _FakeSocket(
            b"HTTP/1.1 200 OK\r\nServer: lab-mdm\r\n\r\n"))
    monkeypatch.setattr(lb.ssl, "create_default_context", lambda: context)

    head = lb._probe_http(8443)

    assert head and head.startswith("HTTP/1.1 200")
    assert context.wrapped == ["127.0.0.1"]
    assert context.check_hostname is False
    assert lb.identify(8443)[0] == "http"


def test_plain_http_ports_do_not_wrap_tls(monkeypatch):
    sock = _FakeSocket(b"HTTP/1.1 200 OK\r\nServer: lab-web\r\n\r\n")
    context = _FakeTlsContext()
    monkeypatch.setattr(lb.socket, "create_connection",
                        lambda *a, **k: sock)
    monkeypatch.setattr(lb.ssl, "create_default_context", lambda: context)

    assert lb._probe_http(8081).startswith("HTTP/1.1 200")
    assert context.wrapped == []


def test_adb_cnxn_packet_is_framed_and_has_the_magic_complement():
    packet = lb._adb_cnxn_packet()
    (length,) = struct.unpack("<I", packet[:4])
    command, _arg0, _arg1, data_len, _crc, magic = struct.unpack(
        "<6I", packet[4:28])
    assert length == len(packet) - 4
    assert command == 0x4E584E43
    assert magic == command ^ 0xFFFFFFFF
    assert data_len == len(packet) - 28
    assert packet[28:] == b"host::\0"


def test_5555_is_identified_only_after_a_real_cnxn_reply(monkeypatch):
    reply = struct.pack("<I", 24) + struct.pack(
        "<6I", 0x4E584E43, 0x01000000, 4096, 0, 0, 0x4E584E43 ^ 0xFFFFFFFF)
    monkeypatch.setattr(lb.socket, "create_connection",
                        lambda *a, **k: _FakeSocket(reply))
    assert lb.identify(5555) == ("adb", "CNXN")


def test_an_open_5555_that_does_not_speak_adb_stays_unknown(monkeypatch):
    monkeypatch.setattr(lb.socket, "create_connection",
                        lambda *a, **k: _FakeSocket(b""))
    assert lb.identify(5555)[0] == "unknown"
