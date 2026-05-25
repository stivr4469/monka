"""
Censys Search API enrichment (Phase 13.B).

API docs: https://search.censys.io/api
Требует CENSYS_API_ID + CENSYS_API_SECRET в env.

Особенности:
- Basic Auth: API ID + API Secret
- Graceful: если credentials не заданы → возвращает пустой результат
- Маппинг портов на severity:
    22/23/3389/5900  → high    (remote access)
    3306/5432/6379/27017 → critical (databases)
    остальное        → info
"""
import logging
import os
import socket
import ipaddress
from typing import Any

import httpx

from tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

_BASE_URL = "https://search.censys.io/api/v2"
_TIMEOUT = 30.0
_MAX_IPS_PER_DOMAIN = 5

# Порты с высоким риском (remote access)
_HIGH_RISK_PORTS = {22, 23, 3389, 5900}

# Критические порты (базы данных / кеши)
_CRITICAL_PORTS = {3306, 5432, 6379, 27017}

# Приватные диапазоны IPv4
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_CENSYS_AVAILABLE = bool(
    os.environ.get("CENSYS_API_ID") and os.environ.get("CENSYS_API_SECRET")
)


def _get_auth() -> tuple[str, str] | None:
    """Возвращает (api_id, api_secret) или None если не настроено."""
    api_id = os.environ.get("CENSYS_API_ID", "")
    api_secret = os.environ.get("CENSYS_API_SECRET", "")
    if not api_id or not api_secret:
        return None
    return (api_id, api_secret)


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
        logger.debug("[censys] DNS-резолв %s не удался: %s", domain, exc)
        return []


def search_censys_hosts(query: str, per_page: int = 25) -> list[dict[str, Any]]:
    """
    Поиск хостов через Censys Search API.
    GET /api/v2/hosts/search?q={query}&per_page={per_page}

    Возвращает список хостов с полями:
    - ip, services (список портов/сервисов), location, autonomous_system
    """
    auth = _get_auth()
    if not auth:
        logger.warning("[censys] API credentials not configured")
        return []

    url = f"{_BASE_URL}/hosts/search"
    params = {"q": query, "per_page": per_page}

    try:
        resp = httpx.get(url, params=params, auth=auth, timeout=_TIMEOUT)

        if resp.status_code == 401:
            logger.warning("[censys] Неверные API credentials — проверьте CENSYS_API_ID/SECRET")
            return []
        if resp.status_code == 429:
            logger.warning("[censys] Rate limit — превышен лимит запросов")
            return []
        if resp.status_code == 422:
            logger.warning("[censys] Некорректный запрос: %s", resp.text[:200])
            return []

        resp.raise_for_status()
        data = resp.json()
        hits = data.get("result", {}).get("hits", [])
        return hits if isinstance(hits, list) else []

    except httpx.TimeoutException:
        logger.debug("[censys] Таймаут запроса search (query=%s)", query[:50])
        return []
    except Exception as exc:
        logger.debug("[censys] Ошибка search запроса: %s", exc)
        return []


def get_censys_host(ip: str) -> dict[str, Any] | None:
    """
    Детальная информация о хосте.
    GET /api/v2/hosts/{ip}
    """
    auth = _get_auth()
    if not auth:
        logger.warning("[censys] API credentials not configured")
        return None

    url = f"{_BASE_URL}/hosts/{ip}"

    try:
        resp = httpx.get(url, auth=auth, timeout=_TIMEOUT)

        if resp.status_code == 404:
            logger.debug("[censys] IP %s не найден в Censys", ip)
            return None
        if resp.status_code == 401:
            logger.warning("[censys] Неверные API credentials для хоста %s", ip)
            return None
        if resp.status_code == 429:
            logger.warning("[censys] Rate limit при запросе хоста %s", ip)
            return None

        resp.raise_for_status()
        data = resp.json()
        return data.get("result", {})

    except httpx.TimeoutException:
        logger.debug("[censys] Таймаут запроса хоста %s", ip)
        return None
    except Exception as exc:
        logger.debug("[censys] Ошибка запроса хоста %s: %s", ip, exc)
        return None


def _classify_port_severity(port: int) -> str:
    """Определяет severity по номеру порта."""
    if port in _CRITICAL_PORTS:
        return "critical"
    if port in _HIGH_RISK_PORTS:
        return "high"
    return "info"


def _extract_ports_from_host(host_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Извлекает список сервисов/портов из ответа Censys."""
    services = host_data.get("services", [])
    if not isinstance(services, list):
        return []
    return services


def enrich_domain_with_censys(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, Any]:
    """
    Полное обогащение домена через Censys:
    1. Ищем хосты через search API (parsed.names: {domain})
    2. Для каждого найденного IP → get_censys_host() для деталей
    3. Формируем события: открытые порты, сервисы, геолокация, AS info
    4. Отправляем в bulk_ingest

    Returns: {"checked": N_ips, "sent": N_events}
    """
    auth = _get_auth()
    if not auth:
        logger.info("[censys] Credentials не заданы — пропускаем enrichment для %s", domain)
        return {"checked": 0, "sent": 0, "skipped": True, "reason": "no_credentials"}

    logger.info("[censys] Начало enrichment для домена %s", domain)

    # Ищем хосты через Search API
    query = f"parsed.names: {domain}"
    hits = search_censys_hosts(query, per_page=_MAX_IPS_PER_DOMAIN)

    # Также резолвим через DNS для полноты картины
    resolved_ips = _resolve_to_ips(domain)
    all_ips: set[str] = set(resolved_ips)

    for hit in hits:
        ip = hit.get("ip")
        if ip and not _is_private_ip(ip):
            all_ips.add(ip)

    if not all_ips:
        logger.info("[censys] Не найдено публичных IP для %s", domain)
        return {"checked": 0, "sent": 0, "skipped": False, "reason": "no_ips"}

    # Ограничиваем число IP
    ips_to_check = list(all_ips)[:_MAX_IPS_PER_DOMAIN]
    events_batch: list[dict[str, Any]] = []

    for ip in ips_to_check:
        host_data = get_censys_host(ip)
        if host_data is None:
            # Пробуем найти данные в hits от search
            host_data = next((h for h in hits if h.get("ip") == ip), None)
        if host_data is None:
            continue

        services = _extract_ports_from_host(host_data)
        location = host_data.get("location", {})
        autonomous_system = host_data.get("autonomous_system", {})

        for svc in services:
            port = svc.get("port")
            if not isinstance(port, int):
                continue

            severity = _classify_port_severity(port)
            transport = svc.get("transport_protocol", "TCP")
            service_name = svc.get("service_name", "unknown")

            events_batch.append({
                "event_type": "port_scan",
                "severity": severity,
                "source_type": "enrichment",
                "source_name": "censys",
                "target_domain": domain,
                "payload": {
                    "ip": ip,
                    "port": port,
                    "transport_protocol": transport,
                    "service_name": service_name,
                    "country": location.get("country"),
                    "city": location.get("city"),
                    "asn": autonomous_system.get("asn"),
                    "as_name": autonomous_system.get("name"),
                },
            })

        # Событие с общей сводкой по хосту (геолокация + AS)
        open_ports = [s.get("port") for s in services if isinstance(s.get("port"), int)]
        if open_ports:
            events_batch.append({
                "event_type": "asset_change",
                "severity": "medium",
                "source_type": "enrichment",
                "source_name": "censys",
                "target_domain": domain,
                "payload": {
                    "ip": ip,
                    "open_ports": open_ports,
                    "country": location.get("country"),
                    "city": location.get("city"),
                    "asn": autonomous_system.get("asn"),
                    "as_name": autonomous_system.get("name"),
                },
            })

        logger.info(
            "[censys] IP %s: сервисов=%d, портов=%d",
            ip, len(services), len(open_ports) if open_ports else 0,
        )

    # Отправляем батч в Core API
    sent_count = 0
    if events_batch:
        result = bulk_ingest(events_batch, core_api_url, internal_secret)
        sent_count = result.get("sent", 0)
        logger.info("[censys] Отправлено %d событий, ошибок=%d", result["sent"], result["errors"])

    return {
        "checked": len(ips_to_check),
        "sent": sent_count,
        "skipped": False,
        "reason": None,
    }
