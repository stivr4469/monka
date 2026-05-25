"""
Воркер сканирования открытых портов через nmap.

Находит открытые сервисы на публичных IP домена.
Каждый открытый порт → NormalizedEvent(event_type="exposed_service", source_name="nmap")

Безопасность:
  - Фильтрация приватных IP (RFC 1918, loopback, link-local) — не сканируем чужую инфраструктуру
  - shell=False в subprocess.run — исключает инъекцию команд
  - Таймаут nmap 120 секунд максимум
"""
import ipaddress
import logging
import socket
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

# Таймаут одного nmap-запуска (секунды)
_NMAP_TIMEOUT = 120

# Таймаут DNS-резолвинга (секунды)
_DNS_TIMEOUT = 10.0

# Порты для сканирования
_SCAN_PORTS = "21,22,23,25,80,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017"

# Карта severity по номеру порта
_PORT_SEVERITY_MAP: dict[int, str] = {
    # Базы данных и кэши — critical (прямой доступ к данным)
    1433:  "critical",  # MSSQL
    1521:  "critical",  # Oracle DB
    3306:  "critical",  # MySQL / MariaDB
    5432:  "critical",  # PostgreSQL
    27017: "critical",  # MongoDB
    6379:  "critical",  # Redis
    9200:  "critical",  # Elasticsearch
    # Небезопасные протоколы и удалённый доступ — high
    21:    "high",      # FTP (plaintext)
    23:    "high",      # Telnet (plaintext)
    3389:  "high",      # RDP
    5900:  "high",      # VNC
    445:   "high",      # SMB (EternalBlue и пр.)
    # Нестандартные HTTP — medium (часто dev/admin-панели)
    8080:  "medium",
    8443:  "medium",
    8888:  "medium",
    # Стандартные HTTP/HTTPS — low
    80:    "low",
    443:   "low",
    # SSH — отдельно: факт наличия — info, проблема — в конфигурации
    22:    "low",
    # SMTP — нестандартно открытый на периметре
    25:    "medium",
}


def _is_private_ip(ip: str) -> bool:
    """
    Проверяет, является ли IP приватным / loopback / link-local.

    Фильтрует RFC 1918 (10.x, 172.16-31.x, 192.168.x),
    loopback (127.x), link-local (169.254.x) и мультикаст (224.x/4).
    Не сканируем локальную и чужую инфраструктуру.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
        )
    except ValueError:
        # Не смогли разобрать — пропускаем
        return True


def _resolve_ip(domain: str) -> list[str]:
    """
    Резолвит домен в список публичных IP-адресов.

    Использует getaddrinfo для поддержки как IPv4, так и IPv6.
    Фильтрует приватные диапазоны — не сканируем localhost / LAN.
    Возвращает дедуплицированный список.
    """
    try:
        socket.setdefaulttimeout(_DNS_TIMEOUT)
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        logger.warning("[port_scanner][resolve] %s: %s", domain, exc)
        return []
    finally:
        socket.setdefaulttimeout(None)

    seen: set[str] = set()
    result: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen and not _is_private_ip(ip):
            seen.add(ip)
            result.append(ip)

    if not result:
        logger.info("[port_scanner][resolve] %s: нет публичных IP (только приватные или не резолвится)", domain)

    return result


def _run_nmap(ip: str) -> list[dict[str, Any]]:
    """
    Запускает nmap для одного IP, парсит XML-вывод.

    Возвращает список открытых портов:
      [{"port": int, "protocol": str, "service": str, "version": str, "ip": str}, ...]

    Выбрасывает FileNotFoundError если nmap не установлен,
    subprocess.TimeoutExpired если превышен таймаут.
    """
    cmd = [
        "nmap",
        "-p", _SCAN_PORTS,
        "--open",            # только открытые порты
        "-T4",               # агрессивный таймаут (без T5 — меньше false positive)
        "-sV",               # определение версий сервисов
        "--version-light",   # лёгкий режим версий (быстрее)
        "-oX", "-",          # вывод в XML на stdout
        ip,
    ]

    # shell=False — обязательно, защита от инъекции команд
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_NMAP_TIMEOUT,
        shell=False,
    )

    if result.returncode not in (0, 1):
        # returncode=1 — nmap нашёл хосты, но с предупреждениями (нормально)
        logger.warning(
            "[port_scanner][nmap] IP=%s rc=%d stderr=%s",
            ip, result.returncode, result.stderr[:200],
        )

    return _parse_nmap_xml(result.stdout, ip)


def _parse_nmap_xml(xml_output: str, ip: str) -> list[dict[str, Any]]:
    """
    Парсит XML-вывод nmap в список словарей с информацией о портах.

    Обрабатывает только порты со state="open".
    При ошибке парсинга возвращает пустой список и логирует предупреждение.
    """
    if not xml_output.strip():
        logger.debug("[port_scanner][xml] Пустой вывод nmap для IP=%s", ip)
        return []

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        logger.warning("[port_scanner][xml] Ошибка разбора XML для IP=%s: %s", ip, exc)
        return []

    ports: list[dict[str, Any]] = []

    for host in root.findall("host"):
        # Берём IP из XML (nmap сам фиксирует адрес); fallback на переданный ip
        addr_elem = host.find("address[@addrtype='ipv4']") or host.find("address[@addrtype='ipv6']")
        host_ip = addr_elem.get("addr", ip) if addr_elem is not None else ip

        for port_elem in host.findall(".//port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            port_id = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")

            service_elem = port_elem.find("service")
            service_name = ""
            service_version = ""
            if service_elem is not None:
                service_name = service_elem.get("name", "")
                # Собираем версию из product + version + extrainfo
                parts = filter(None, [
                    service_elem.get("product", ""),
                    service_elem.get("version", ""),
                    service_elem.get("extrainfo", ""),
                ])
                service_version = " ".join(parts)

            ports.append({
                "port":     port_id,
                "protocol": protocol,
                "service":  service_name,
                "version":  service_version,
                "ip":       host_ip,
            })

    return ports


def _port_severity(port_data: dict[str, Any]) -> str:
    """
    Определяет severity события по номеру порта.

    Неизвестные порты получают severity="medium" —
    любой неожиданный открытый порт требует внимания.
    """
    return _PORT_SEVERITY_MAP.get(port_data["port"], "medium")


def run_port_scan(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, Any]:
    """
    Основная функция: сканирует открытые порты домена через nmap.

    1. Резолвит домен в публичные IP
    2. Для каждого IP запускает nmap
    3. Каждый открытый порт → событие exposed_service в Core API
    4. Батчевая отправка через bulk_ingest

    Возвращает: {"domain": str, "ips_scanned": N, "ports_found": M, "sent": K}
    """
    domain = domain.strip().lower()
    logger.info("[port_scanner] Начало сканирования domain=%s", domain)

    # Резолвим домен
    public_ips = _resolve_ip(domain)
    if not public_ips:
        logger.warning("[port_scanner] domain=%s: нет публичных IP — сканирование пропущено", domain)
        return {"error": "no_public_ips", "domain": domain}

    logger.info("[port_scanner] domain=%s public_ips=%s", domain, public_ips)

    # Сканируем каждый IP
    all_ports: list[dict[str, Any]] = []
    ips_scanned = 0

    for ip in public_ips:
        try:
            ports = _run_nmap(ip)
            all_ports.extend(ports)
            ips_scanned += 1
            logger.info("[port_scanner] IP=%s: найдено портов=%d", ip, len(ports))
        except FileNotFoundError:
            # nmap не установлен — отправляем info-событие и прекращаем
            logger.error("[port_scanner] nmap не найден. Установите: apt-get install nmap")
            _send_nmap_unavailable(domain, core_api_url, internal_secret)
            return {"error": "nmap_not_found", "domain": domain}
        except subprocess.TimeoutExpired:
            logger.warning("[port_scanner] Таймаут nmap для IP=%s (%ds)", ip, _NMAP_TIMEOUT)
        except Exception as exc:
            logger.error("[port_scanner] Ошибка сканирования IP=%s: %s", ip, exc)

    # Формируем события
    events: list[dict[str, Any]] = [
        {
            "event_type": "exposed_service",
            "severity":   _port_severity(port_data),
            "source_type": "scanner",
            "source_name": "nmap",
            "target_domain": domain,
            "payload": {
                "port":    port_data["port"],
                "service": port_data["service"],
                "version": port_data["version"],
                "ip":      port_data["ip"],
            },
        }
        for port_data in all_ports
    ]

    # Батчевая отправка в Core API
    sent = 0
    if events:
        result = bulk_ingest(events, core_api_url, internal_secret)
        sent = result.get("sent", 0)
        if result.get("errors", 0):
            logger.warning(
                "[port_scanner] domain=%s: ошибки доставки events errors=%d",
                domain, result["errors"],
            )

    logger.info(
        "[port_scanner] Итого domain=%s ips_scanned=%d ports_found=%d sent=%d",
        domain, ips_scanned, len(all_ports), sent,
    )
    return {
        "domain":      domain,
        "ips_scanned": ips_scanned,
        "ports_found": len(all_ports),
        "sent":        sent,
    }


def run_port_scan_all_assets() -> None:
    """
    10.H: Celery Beat задача — сканирование портов всех активных активов.

    Запрашивает список активов через Core API и запускает сканирование каждого.
    Используется как stub для Beat расписания — реальная логика через run_port_scan().
    """
    import os

    import httpx

    core_url = os.environ.get("CORE_API_URL", "http://core:8000")
    internal_secret = os.environ.get("INTERNAL_API_SECRET", "")

    try:
        resp = httpx.get(
            f"{core_url}/api/v1/assets/",
            headers={"Authorization": f"Bearer {internal_secret}"},
            timeout=10,
        )
        assets = resp.json() if resp.is_success else []
        logger.info("[beat] port-scan-all: запускаем для %d активов", len(assets))
        for asset in assets:
            domain = asset.get("domain") if isinstance(asset, dict) else None
            if domain:
                try:
                    run_port_scan(
                        domain=domain,
                        core_api_url=core_url,
                        internal_secret=internal_secret,
                    )
                except Exception as exc:
                    logger.warning("[beat] port-scan-all: ошибка для %s: %s", domain, exc)
    except Exception as exc:
        logger.warning("[beat] port-scan-all: ошибка получения активов: %s", exc)


def _send_nmap_unavailable(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> None:
    """
    Отправляет info-событие если nmap не установлен.
    Позволяет зафиксировать факт недоступности инструмента в системе событий.
    """
    event: dict[str, Any] = {
        "event_type":   "exposed_service",
        "severity":     "info",
        "source_type":  "scanner",
        "source_name":  "nmap",
        "target_domain": domain,
        "payload": {
            "error":   "nmap_unavailable",
            "message": "nmap не установлен на сервере. Сканирование портов недоступно.",
        },
    }
    try:
        bulk_ingest([event], core_api_url, internal_secret)
    except Exception as exc:
        logger.error("[port_scanner] Ошибка отправки nmap_unavailable: %s", exc)
