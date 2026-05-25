"""
Воркер быстрого сканирования IP-диапазонов через masscan + уточнение сервисов через nmap.

masscan сканирует /24 за секунды (rate 500 pps), затем nmap уточняет версии сервисов.
Каждый открытый порт → NormalizedEvent(event_type="exposed_service", source_name="masscan")

Безопасность:
  - shell=False во всех subprocess.run — исключает инъекцию команд
  - Фильтрация приватных IP (RFC 1918, loopback, link-local) — не сканируем чужую инфраструктуру
  - Таймаут masscan 120 сек, nmap 30 сек на порт
"""
import ipaddress
import json
import logging
import socket
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

# Таймаут masscan-запуска (секунды)
_MASSCAN_TIMEOUT = 120

# Таймаут одного nmap-уточнения (секунды)
_NMAP_FINGERPRINT_TIMEOUT = 30

# Таймаут DNS-резолвинга (секунды)
_DNS_TIMEOUT = 10.0

# Порты для masscan-сканирования
_DEFAULT_PORTS = "1-1024,3306,5432,6379,8080,8443,27017"

# Карта severity по номеру порта
_PORT_SEVERITY: dict[int, str] = {
    # Базы данных и кэши — critical (прямой доступ к данным)
    3306:  "critical",   # MySQL / MariaDB
    5432:  "critical",   # PostgreSQL
    6379:  "critical",   # Redis
    27017: "critical",   # MongoDB
    9200:  "critical",   # Elasticsearch
    # Небезопасные протоколы и удалённый доступ — high
    22:    "high",       # SSH (факт публичной доступности)
    23:    "high",       # Telnet (plaintext)
    3389:  "high",       # RDP
    5900:  "high",       # VNC
}


def _is_private_ip(ip: str) -> bool:
    """
    Возвращает True если IP приватный / loopback / link-local / multicast.

    Фильтрует RFC 1918 (10.x, 172.16-31.x, 192.168.x),
    loopback (127.x), link-local (169.254.x), мультикаст (224.x/4).
    При невалидном адресе возвращает True — пропускаем безопасно.
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
        return True


def resolve_ips(domain: str) -> list[str]:
    """
    Резолвит домен в список публичных IP-адресов.

    Использует socket.getaddrinfo для поддержки IPv4 и IPv6.
    Фильтрует приватные диапазоны — не сканируем localhost / LAN.
    Возвращает дедуплицированный список или [] при ошибке резолвинга.
    """
    try:
        socket.setdefaulttimeout(_DNS_TIMEOUT)
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        logger.warning("[masscan_scanner][resolve] %s: %s", domain, exc)
        return []
    finally:
        # Восстанавливаем дефолтный таймаут чтобы не влиять на другие операции
        socket.setdefaulttimeout(None)

    seen: set[str] = set()
    result: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen and not _is_private_ip(ip):
            seen.add(ip)
            result.append(ip)

    if not result:
        logger.info(
            "[masscan_scanner][resolve] %s: нет публичных IP (только приватные или не резолвится)",
            domain,
        )

    return result


def run_masscan(
    targets: list[str],
    ports: str = _DEFAULT_PORTS,
) -> list[dict[str, Any]]:
    """
    Запускает masscan для списка IP-адресов, парсит JSON-вывод.

    Возвращает список открытых портов:
      [{"ip": str, "port": int, "proto": str}, ...]

    Возвращает [] если:
      - masscan не установлен (FileNotFoundError) — graceful fallback
      - timeout 120 сек превышен
      - вывод пустой или невалидный JSON
    """
    if not targets:
        return []

    # shell=False обязательно — защита от инъекции команд через имена хостов
    cmd = ["masscan"] + targets + [
        "-p", ports,
        "--rate=500",   # консервативный rate — не флудить чужие сети
        "-oJ", "-",     # JSON-вывод на stdout
        "--wait=3",     # ждать 3 сек после последнего пакета
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_MASSCAN_TIMEOUT,
            shell=False,   # SECURITY: никогда shell=True для пользовательского ввода
        )
    except FileNotFoundError:
        logger.warning(
            "[masscan_scanner] masscan не найден. "
            "Установите: apt-get install masscan"
        )
        return []
    except subprocess.TimeoutExpired:
        logger.warning("[masscan_scanner] Таймаут masscan (%ds) для targets=%s", _MASSCAN_TIMEOUT, targets)
        return []
    except Exception as exc:
        logger.error("[masscan_scanner] Ошибка запуска masscan: %s", exc)
        return []

    return _parse_masscan_json(proc.stdout)


def _parse_masscan_json(output: str) -> list[dict[str, Any]]:
    """
    Парсит JSON-вывод masscan в список словарей с открытыми портами.

    masscan выводит каждый результат отдельной строкой (не валидный JSON-массив целиком):
      { "ip": "1.2.3.4", "ports": [{"port": 80, "proto": "tcp", "status": "open", ...}] }

    Пропускает строки, которые не парсятся (заголовок/комментарии masscan).
    """
    results: list[dict[str, Any]] = []

    if not output.strip():
        return results

    for line in output.splitlines():
        line = line.strip()
        # Пропускаем строки-разделители masscan (начинаются с [ или содержат только скобки)
        if not line or line in ("[", "]", ","):
            continue
        # Убираем trailing-запятую — masscan добавляет её в конце некоторых строк
        if line.endswith(","):
            line = line[:-1]
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("[masscan_scanner] Пропускаем невалидную строку: %r", line[:80])
            continue

        ip = record.get("ip", "")
        for port_info in record.get("ports", []):
            port = port_info.get("port")
            proto = port_info.get("proto", "tcp")
            status = port_info.get("status", "")
            # Берём только открытые порты
            if port and status == "open":
                results.append({"ip": ip, "port": int(port), "proto": proto})

    return results


def fingerprint_with_nmap(ip: str, port: int) -> dict[str, str]:
    """
    Уточняет сервис на конкретном порту через nmap -sV.

    Возвращает {"service": str, "version": str, "product": str}
    или пустой dict если nmap не установлен / таймаут / не определено.
    """
    cmd = [
        "nmap",
        "-sV",          # определение версий сервисов
        f"-p{port}",    # только конкретный порт — быстрее
        "--open",       # только открытые
        "-T4",          # агрессивный таймаут
        "-oX", "-",     # XML на stdout
        ip,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_NMAP_FINGERPRINT_TIMEOUT,
            shell=False,   # SECURITY: shell=False обязательно
        )
    except FileNotFoundError:
        logger.warning("[masscan_scanner] nmap не найден для fingerprint IP=%s port=%d", ip, port)
        return {}
    except subprocess.TimeoutExpired:
        logger.warning("[masscan_scanner] Таймаут nmap fingerprint IP=%s port=%d", ip, port)
        return {}
    except Exception as exc:
        logger.error("[masscan_scanner] Ошибка nmap fingerprint IP=%s port=%d: %s", ip, port, exc)
        return {}

    return _parse_nmap_xml_fingerprint(proc.stdout)


def _parse_nmap_xml_fingerprint(xml_output: str) -> dict[str, str]:
    """
    Парсит XML-вывод nmap -sV, возвращает информацию о сервисе.

    Собирает поля: service name, product, version, extrainfo.
    При ошибке парсинга или отсутствии данных возвращает пустой dict.
    """
    if not xml_output.strip():
        return {}

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        logger.warning("[masscan_scanner] Ошибка разбора XML nmap: %s", exc)
        return {}

    # Ищем первый открытый порт в выводе nmap
    for host in root.findall("host"):
        for port_elem in host.findall(".//port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            service_elem = port_elem.find("service")
            if service_elem is None:
                return {"service": "", "version": "", "product": ""}

            service_name = service_elem.get("name", "")
            product = service_elem.get("product", "")
            # Собираем строку версии из product + version + extrainfo
            version_parts = filter(None, [
                service_elem.get("version", ""),
                service_elem.get("extrainfo", ""),
            ])
            version_str = " ".join(version_parts)

            return {
                "service": service_name,
                "version": version_str,
                "product": product,
            }

    return {}


def _get_severity(port: int) -> str:
    """
    Определяет severity события по номеру порта.

    Логика:
      - Базы данных (MySQL/PG/Redis/MongoDB/ES) → critical
      - SSH/Telnet/RDP/VNC → high
      - Всё остальное → medium (любой неожиданный открытый порт требует внимания)
    """
    return _PORT_SEVERITY.get(port, "medium")


def scan_domain(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, Any]:
    """
    Основная функция: быстрое сканирование домена через masscan + уточнение через nmap.

    Пайплайн:
      1. resolve_ips(domain) → список публичных IP
      2. run_masscan(ips) → список открытых портов
      3. Для каждого порта → fingerprint_with_nmap() → название сервиса и версия
      4. Формирование NormalizedEvent для каждого открытого порта
      5. bulk_ingest(events) → отправка в Core API

    Возвращает:
      {"ips_scanned": N, "ports_found": N, "sent": N} при успехе
      {"error": "no_ips", "sent": 0} если домен не резолвится в публичные IP
    """
    domain = domain.strip().lower()
    logger.info("[masscan_scanner] Начало сканирования domain=%s", domain)

    # Резолвим домен в публичные IP
    ips = resolve_ips(domain)
    if not ips:
        logger.warning("[masscan_scanner] domain=%s: нет публичных IP — сканирование пропущено", domain)
        return {"error": "no_ips", "sent": 0}

    logger.info("[masscan_scanner] domain=%s ips=%s", domain, ips)

    # Запускаем masscan по всем IP сразу (эффективнее одного запуска)
    open_ports = run_masscan(ips)
    logger.info("[masscan_scanner] domain=%s: masscan нашёл портов=%d", domain, len(open_ports))

    # Формируем события для каждого открытого порта
    events: list[dict[str, Any]] = []
    for port_data in open_ports:
        ip = port_data["ip"]
        port = port_data["port"]
        proto = port_data["proto"]

        # Уточняем сервис через nmap только если masscan что-то нашёл
        fingerprint = fingerprint_with_nmap(ip, port)
        service = fingerprint.get("service", "")
        version = fingerprint.get("version", "")
        product = fingerprint.get("product", "")

        event: dict[str, Any] = {
            "event_type": "exposed_service",
            "severity": _get_severity(port),
            "source_type": "scanner",
            "source_name": "masscan",
            "target_domain": domain,
            "payload": {
                "ip": ip,
                "port": port,
                "proto": proto,
                "service": service,
                "version": version,
                "product": product,
                "scanner": "masscan+nmap",
            },
        }
        events.append(event)

    # Батчевая отправка событий в Core API
    sent = 0
    if events:
        result = bulk_ingest(events, core_api_url, internal_secret)
        sent = result.get("sent", 0)
        if result.get("errors", 0):
            logger.warning(
                "[masscan_scanner] domain=%s: ошибки доставки errors=%d",
                domain, result["errors"],
            )

    logger.info(
        "[masscan_scanner] Итого domain=%s ips_scanned=%d ports_found=%d sent=%d",
        domain, len(ips), len(open_ports), sent,
    )
    return {
        "ips_scanned": len(ips),
        "ports_found": len(open_ports),
        "sent": sent,
    }
