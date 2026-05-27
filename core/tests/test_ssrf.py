"""Unit-тесты для SSRF-защиты (app.core.ssrf.is_safe_url)."""
from unittest.mock import patch

import pytest

from app.core.ssrf import is_safe_url


# ── Тесты: заблокированные адреса ────────────────────────────────────────────

class TestSsrfBlocked:
    """URL, которые должны быть заблокированы SSRF-защитой."""

    def test_loopback_ipv4(self) -> None:
        """127.0.0.1 — loopback, должен быть заблокирован."""
        assert is_safe_url("http://127.0.0.1/admin") is False

    def test_loopback_ipv4_range(self) -> None:
        """127.0.0.2 — всё /8 loopback, должен быть заблокирован."""
        assert is_safe_url("http://127.0.0.2/secret") is False

    def test_private_class_a(self) -> None:
        """10.x.x.x — RFC 1918 Class A, должен быть заблокирован."""
        assert is_safe_url("https://10.0.0.1/") is False

    def test_private_class_b(self) -> None:
        """172.16.x.x — RFC 1918 Class B, должен быть заблокирован."""
        assert is_safe_url("https://172.16.0.1/") is False

    def test_private_class_b_upper(self) -> None:
        """172.31.x.x — RFC 1918 Class B верхняя граница."""
        assert is_safe_url("http://172.31.255.254/") is False

    def test_private_class_c(self) -> None:
        """192.168.x.x — RFC 1918 Class C, должен быть заблокирован."""
        assert is_safe_url("http://192.168.1.1/") is False

    def test_link_local_apipa(self) -> None:
        """169.254.x.x — link-local (APIPA), должен быть заблокирован."""
        assert is_safe_url("http://169.254.169.254/latest/meta-data/") is False

    def test_aws_metadata_endpoint(self) -> None:
        """AWS Instance Metadata — классический SSRF-вектор."""
        assert is_safe_url("http://169.254.169.254/latest/meta-data/iam/") is False

    def test_cgnat(self) -> None:
        """100.64.x.x — CGNAT RFC 6598, должен быть заблокирован."""
        assert is_safe_url("http://100.64.0.1/") is False

    def test_ipv6_loopback(self) -> None:
        """::1 — IPv6 loopback, должен быть заблокирован."""
        assert is_safe_url("http://[::1]/") is False

    def test_ipv6_link_local(self) -> None:
        """fe80:: — IPv6 link-local, должен быть заблокирован."""
        assert is_safe_url("http://[fe80::1]/") is False

    def test_ipv6_ula(self) -> None:
        """fc00:: — IPv6 ULA (RFC 4193), должен быть заблокирован."""
        assert is_safe_url("http://[fc00::1]/") is False

    def test_invalid_scheme_file(self) -> None:
        """file:// схема → заблокирована."""
        assert is_safe_url("file:///etc/passwd") is False

    def test_invalid_scheme_ftp(self) -> None:
        """ftp:// схема → заблокирована."""
        assert is_safe_url("ftp://example.com/file.txt") is False

    def test_invalid_scheme_dict(self) -> None:
        """dict:// схема → заблокирована."""
        assert is_safe_url("dict://localhost:11211/") is False

    def test_empty_url(self) -> None:
        """Пустая строка → заблокирована."""
        assert is_safe_url("") is False

    def test_no_scheme(self) -> None:
        """URL без схемы → заблокирован."""
        assert is_safe_url("example.com") is False

    def test_no_host(self) -> None:
        """URL без хоста → заблокирован."""
        assert is_safe_url("http:///path") is False

    def test_dns_resolves_to_loopback(self) -> None:
        """DNS-имя, резолвящееся в loopback → заблокировано."""
        with patch("app.core.ssrf.socket.gethostbyname", return_value="127.0.0.1"):
            assert is_safe_url("http://localhost.example.com/") is False

    def test_dns_resolves_to_private(self) -> None:
        """DNS-имя, резолвящееся в RFC 1918 → заблокировано."""
        with patch("app.core.ssrf.socket.gethostbyname", return_value="192.168.1.100"):
            assert is_safe_url("https://internal.corp/api") is False

    def test_dns_resolution_failure(self) -> None:
        """Ошибка DNS-резолва → fail-closed (заблокировано)."""
        import socket as _socket
        with patch("app.core.ssrf.socket.gethostbyname", side_effect=_socket.gaierror):
            assert is_safe_url("https://nonexistent.invalid/") is False


# ── Тесты: разрешённые адреса ─────────────────────────────────────────────────

class TestSsrfAllowed:
    """URL, которые должны быть пропущены SSRF-защитой."""

    def test_public_http(self) -> None:
        """Публичный HTTP URL → разрешён."""
        with patch("app.core.ssrf.socket.gethostbyname", return_value="93.184.216.34"):
            assert is_safe_url("http://example.com/") is True

    def test_public_https(self) -> None:
        """Публичный HTTPS URL → разрешён."""
        with patch("app.core.ssrf.socket.gethostbyname", return_value="8.8.8.8"):
            assert is_safe_url("https://google.com/") is True

    def test_direct_public_ipv4(self) -> None:
        """Прямой публичный IPv4 → разрешён."""
        assert is_safe_url("https://8.8.8.8/") is True

    def test_direct_public_ipv4_with_port(self) -> None:
        """Публичный IP с нестандартным портом → разрешён."""
        assert is_safe_url("https://8.8.8.8:8443/check") is True

    def test_public_with_path_and_params(self) -> None:
        """Публичный URL с путём и параметрами → разрешён."""
        with patch("app.core.ssrf.socket.gethostbyname", return_value="93.184.216.34"):
            assert is_safe_url("https://example.com/api/v1/status?token=abc") is True

    def test_subdomain_resolves_public(self) -> None:
        """Субдомен, резолвящийся в публичный IP → разрешён."""
        with patch("app.core.ssrf.socket.gethostbyname", return_value="104.21.0.1"):
            assert is_safe_url("https://sub.example.com/") is True
