"""
SSRF-защита для EASM-платформы.

Блокирует исходящие HTTP-запросы к внутренним, loopback и link-local адресам,
предотвращая атаки Server-Side Request Forgery.

Использование:
    from app.core.ssrf import is_safe_url

    if not is_safe_url(url):
        raise HTTPException(status_code=400, detail="SSRF: небезопасный URL")
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Приватные и зарезервированные сети RFC 1918 + loopback + link-local + Tor + CGNAT
_PRIVATE_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # IPv4 loopback
    ipaddress.ip_network("127.0.0.0/8"),
    # RFC 1918 — приватные диапазоны
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Link-local (APIPA)
    ipaddress.ip_network("169.254.0.0/16"),
    # CGNAT (Carrier-grade NAT) — RFC 6598
    ipaddress.ip_network("100.64.0.0/10"),
    # Документационные диапазоны (TEST-NET)
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    # Multicast
    ipaddress.ip_network("224.0.0.0/4"),
    # Broadcast
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 loopback
    ipaddress.ip_network("::1/128"),
    # IPv6 link-local
    ipaddress.ip_network("fe80::/10"),
    # IPv6 ULA (Unique Local Address — аналог RFC 1918)
    ipaddress.ip_network("fc00::/7"),
]


def _addr_in_private_range(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Проверяет, входит ли IP-адрес в один из приватных диапазонов."""
    return any(addr in net for net in _PRIVATE_NETS)


def is_safe_url(url: str) -> bool:
    """
    Блокирует SSRF — запросы к внутренним/loopback адресам.

    Проверяет:
    1. Схема — только http или https.
    2. Хост присутствует.
    3. IP-адрес (или DNS-резолв хоста) не попадает в приватные диапазоны.

    Возвращает True если URL безопасен, False — если запрос нужно заблокировать.

    DNS-резолв выполняется синхронно (socket.gethostbyname).
    При ошибке резолва считаем URL небезопасным (fail-closed).

    Args:
        url: Полный URL с схемой (например "https://example.com/path").

    Returns:
        True  — URL безопасен для исходящего запроса.
        False — URL небезопасен (SSRF), запрос нужно заблокировать.
    """
    try:
        parsed = urlparse(url)

        # Проверяем схему
        if parsed.scheme not in ("http", "https"):
            logger.warning("[ssrf] Заблокирован: неверная схема '%s' для %s", parsed.scheme, url)
            return False

        host = parsed.hostname or ""
        if not host:
            logger.warning("[ssrf] Заблокирован: отсутствует хост в %s", url)
            return False

        # Пробуем разобрать хост как IP-адрес напрямую
        try:
            addr = ipaddress.ip_address(host)
            if _addr_in_private_range(addr):
                logger.warning(
                    "[ssrf] Заблокирован: приватный IP %s в URL %s",
                    host,
                    url,
                )
                return False
            return True
        except ValueError:
            # Хост — DNS-имя, выполняем резолв
            pass

        # DNS-резолв: fail-closed — при ошибке блокируем
        try:
            resolved_ip = socket.gethostbyname(host)
            addr = ipaddress.ip_address(resolved_ip)
            if _addr_in_private_range(addr):
                logger.warning(
                    "[ssrf] Заблокирован: %s резолвится в приватный IP %s (URL: %s)",
                    host,
                    resolved_ip,
                    url,
                )
                return False
        except OSError as exc:
            # DNS не резолвится — блокируем (fail-closed)
            logger.warning(
                "[ssrf] Заблокирован: DNS-ошибка для %s: %s (URL: %s)",
                host,
                exc,
                url,
            )
            return False

        return True

    except Exception as exc:
        logger.warning("[ssrf] Заблокирован: непредвиденная ошибка при проверке %s: %s", url, exc)
        return False
