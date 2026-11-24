import socket
import pytest

from app.scanner.ssrf_guard import (
    SSRFBlockedError,
    is_public_ip,
    resolve_and_validate_host,
)


def test_is_public_ip_checks():
    assert is_public_ip("93.184.216.34") is True
    assert is_public_ip("1.1.1.1") is True
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("10.0.0.5") is False
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("169.254.169.254") is False
    assert is_public_ip("not-an-ip") is False


def test_resolve_blocks_private_dns(monkeypatch):
    def fake_getaddrinfo(hostname, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(SSRFBlockedError):
        resolve_and_validate_host("://example.com")


def test_resolve_allows_public_dns(monkeypatch):
    def fake_getaddrinfo(hostname, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    ips = resolve_and_validate_host("example.com")
    assert ips == ["93.184.216.34"]