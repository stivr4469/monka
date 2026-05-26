"""
Воркер: обогащение данных через Shodan API (задача 9.J).

Shodan содержит исторические данные о сканах — можно найти порты которые были
открыты вчера но сейчас закрыты файрволом (Asset Drift через историю).

Особенности реализации:
- Бесплатный план Shodan: 1 запрос/секунда — rate-limit через time.sleep(1)
- Graceful: если SHODAN_API_KEY не задан → возвращаем skipped, не ошибку
- Приватные IP фильтруются до запроса к Shodan
- Максимум 5 IP на домен (не спамим API)
"""
import ipaddress
import logging
import os
import socket
import time
from typing import Any

import httpx

from workers.tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

_SHODAN_API_URL = "https://api.shodan.io/shodan/host/{ip}?key={key}"
_REQUEST_TIMEOUT = 15
_MAX_IPS_PER_DOMAIN = 5
_RATE_LIMIT_SLEEP = 1.0  # секунды между запросами (бесплатный план Shodan)

# Приватные диапазоны IPv4 (RFC 1918, loopback, link-local)
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private_ip(ip_str: str) -> bool:
    """Возвращает True если IP приватный / loopback / link-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True  # невалидный IP — пропускаем


def _resolve_to_ips(domain: str) -> list[str]:
    """
    Резолвит домен в публичные IPv4.
    Фильтрует приватные адреса.
    Возвращает максимум _MAX_IPS_PER_DOMAIN адресов.
    """
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        seen: set[str] = set()
        public_ips: list[str] = []
        for info in results:
            ip = info[4][0]
            if ip in seen:
                continue
            seen.add(ip)
            if not _is_private_ip(ip):
                public_ips.append(ip)
            if len(public_ips) >= _MAX_IPS_PER_DOMAIN:
                break
        return public_ips
    except (socket.gaierror, OSError) as exc:
        logger.debug("[shodan] DNS-резолв %s не удался: %s", domain, exc)
        return []


def _query_shodan(ip: str, api_key: str) -> dict[str, Any] | None:
    """
    Запрашивает Shodan API для одного IP.
    Возвращает None при 404 (неизвестный IP), ошибке авторизации или сетевой ошибке.
    """
    url = _SHODAN_API_URL.format(ip=ip, key=api_key)
    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            resp = client.get(url)

        if resp.status_code == 404:
            # Shodan не знает этот IP — не ошибка
            logger.debug("[shodan] IP %s не найден в Shodan", ip)
            return None
        if resp.status_code == 401:
            logger.warning("[shodan] Неверный API ключ — проверьте SHODAN_API_KEY")
            return None
        if resp.status_code == 429:
            logger.warning("[shodan] Rate limit — превышен лимит запросов")
            return None

        resp.raise_for_status()
        return resp.json()

    except httpx.TimeoutException:
        logger.debug("[shodan] Таймаут запроса к Shodan для %s", ip)
        return None
    except Exception as exc:
        logger.debug("[shodan] Ошибка запроса к %s: %s", ip, exc)
        return None


def _extract_ports(shodan_data: dict[str, Any]) -> list[int]:
    """Извлекает список открытых портов из ответа Shodan."""
    raw = shodan_data.get("ports", [])
    return [int(p) for p in raw if isinstance(p, (int, str)) and str(p).isdigit()]


def _mask_api_key(key: str) -> str:
    """Маскирует API ключ для логов (первые 4 символа + ***)."""
    if not key or len(key) < 4:
        return "***"
    return key[:4] + "***"


def run_shodan_enrichment(
    domain: str,
    core_api_url: str,
    internal_secret: str,
    known_ports: list[int] | None = None,
) -> dict[str, Any]:
    """
    Обогащение данных о домене через Shodan API.

    Алгоритм:
    1. Проверяем наличие SHODAN_API_KEY → skipped если нет
    2. Резолвим домен в публичные IPv4 (макс. 5 IP)
    3. Для каждого IP запрашиваем Shodan (с rate-limit 1 req/sec)
    4. Сравниваем исторические порты Shodan с known_ports:
       - Порты у Shodan, но отсутствующие в known_ports → hidden_ports (asset_drift)
       - Новые порты которых Shodan не знает → уже поймали через port_scanner
    5. Отправляем события через bulk_ingest

    Args:
        domain: целевой домен
        core_api_url: URL Core API для ingest
        internal_secret: INTERNAL_API_SECRET
        known_ports: список портов из нашего собственного скана (опционально)

    Returns:
        {
            "ips_checked": N,
            "hidden_ports_found": M,
            "skipped": bool,
            "reason": str | None
        }
    """
    api_key = os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        logger.info("[shodan] SHODAN_API_KEY не задан — пропускаем enrichment")
        return {"status": "skipped", "reason": "no_api_key", "ips_checked": 0, "hidden_ports_found": 0, "skipped": True}

    logger.info("[shodan] Enrichment для %s (ключ: %s)", domain, _mask_api_key(api_key))

    ips = _resolve_to_ips(domain)
    if not ips:
        logger.info("[shodan] Не удалось резолвить публичные IP для %s", domain)
        return {"status": "ok", "reason": "no_ips", "ips_checked": 0, "hidden_ports_found": 0, "skipped": False}

    known_ports_set: set[int] = set(known_ports or [])
    events_batch: list[dict[str, Any]] = []
    total_hidden_ports = 0

    for idx, ip in enumerate(ips):
        # Rate-limit: 1 запрос/сек (бесплатный план Shodan)
        if idx > 0:
            time.sleep(_RATE_LIMIT_SLEEP)

        shodan_data = _query_shodan(ip, api_key)
        if shodan_data is None:
            continue

        shodan_ports = _extract_ports(shodan_data)

        # Скрытые порты: Shodan знает, а в нашем скане нет
        # (могли быть закрыты файрволом после последнего скана Shodan)
        hidden_ports: list[int] = (
            [p for p in shodan_ports if p not in known_ports_set]
            if known_ports_set
            else []
        )
        total_hidden_ports += len(hidden_ports)

        # Новые порты: мы нашли, Shodan не знает → уже покрыты port_scanner'ом
        shodan_ports_set = set(shodan_ports)
        new_ports = [p for p in known_ports_set if p not in shodan_ports_set]

        severity = "medium" if new_ports else ("low" if hidden_ports else "info")

        events_batch.append({
            "event_type": "asset_drift",
            "severity": severity,
            "source_type": "enrichment",
            "source_name": "shodan",
            "target_domain": domain,
            "payload": {
                "ip": ip,
                "shodan_ports": shodan_ports,
                "shodan_country": shodan_data.get("country_name"),
                "shodan_org": shodan_data.get("org"),
                "shodan_last_update": shodan_data.get("last_update"),
                # Порты у Shodan, но не в нашем скане — возможно исторические
                "hidden_ports": hidden_ports,
                # Новые порты которые Shodan не знает — уже поймали port_scanner'ом
                "new_ports": new_ports,
            },
        })

        logger.info(
            "[shodan] IP %s: shodan_ports=%d, hidden=%d, new=%d",
            ip, len(shodan_ports), len(hidden_ports), len(new_ports),
        )

    # Отправляем батч в Core API
    if events_batch:
        result = bulk_ingest(events_batch, core_api_url, internal_secret)
        logger.info("[shodan] Sent %d events, errors=%d", result["sent"], result["errors"])

    return {
        "status": "ok",
        "reason": None,
        "ips_checked": len(ips),
        "hidden_ports_found": total_hidden_ports,
        "skipped": False,
    }
