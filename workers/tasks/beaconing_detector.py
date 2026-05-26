"""
Детектор beaconing-активности — проверка IP-адресов домена по репутационным фидам.

Алгоритм:
  1. Резолвим домен и все субдомены → получаем список IP
  2. Проверяем каждый IP по фидам: Feodo Tracker, URLhaus, ThreatFox (abuse.ch)
  3. Найденные совпадения → событие event_type=malware_beaconing

Фиды (бесплатные, без API-ключа):
  - Feodo Tracker C2: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
  - URLhaus malware URLs: https://urlhaus-api.abuse.ch/v1/host/ (lookup API)
  - ThreatFox IOC: https://threatfox-api.abuse.ch/api/v1/ (lookup API)
"""
from __future__ import annotations

import csv
import io
import logging
import socket
from datetime import datetime, timezone
from typing import Any

import httpx

from tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 15.0
_DNS_TIMEOUT  = 3.0

# Feodo Tracker — CSV с C2-адресами ботнетов (Emotet, QakBot, IcedID и др.)
_FEODO_CSV_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

# Кэш фида в памяти процесса (обновляется при каждом вызове модуля)
_feodo_cache: set[str] = set()
_feodo_loaded = False


def _load_feodo_feed() -> set[str]:
    """Скачивает и парсит Feodo Tracker IP-blocklist."""
    global _feodo_cache, _feodo_loaded
    if _feodo_loaded:
        return _feodo_cache

    ips: set[str] = set()
    try:
        resp = httpx.get(_FEODO_CSV_URL, timeout=_HTTP_TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        reader = csv.reader(io.StringIO(resp.text))
        for row in reader:
            # Формат: # comment или ip,port,status,hostname,as_number,country,date
            if not row or row[0].startswith("#"):
                continue
            if len(row) >= 1:
                ip = row[0].strip()
                if ip:
                    ips.add(ip)
        _feodo_cache = ips
        _feodo_loaded = True
        logger.info("[beaconing] Feodo Tracker загружен: %d C2 IP-адресов", len(ips))
    except Exception as exc:
        logger.warning("[beaconing] Не удалось загрузить Feodo Tracker: %s", exc)
    return ips


def _lookup_urlhaus(ip: str) -> dict[str, Any] | None:
    """Проверяет IP в URLhaus. Возвращает данные если IP замечен в malware-кампаниях."""
    try:
        resp = httpx.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": ip},
            timeout=_HTTP_TIMEOUT,
        )
        data = resp.json()
        if data.get("query_status") == "is_host" and data.get("urls"):
            return {
                "source": "urlhaus",
                "urls_count": len(data["urls"]),
                "tags": list({tag for u in data["urls"] for tag in u.get("tags", []) if tag}),
                "malware_families": list({u.get("threat", "") for u in data["urls"] if u.get("threat")}),
            }
    except Exception as exc:
        logger.debug("[beaconing] URLhaus lookup %s: %s", ip, exc)
    return None


def _lookup_threatfox(ip: str) -> dict[str, Any] | None:
    """Проверяет IP в ThreatFox IOC database."""
    try:
        resp = httpx.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ip},
            timeout=_HTTP_TIMEOUT,
        )
        data = resp.json()
        if data.get("query_status") == "ok" and data.get("data"):
            iocs = data["data"]
            return {
                "source": "threatfox",
                "ioc_count": len(iocs),
                "malware_families": list({i.get("malware_printable", "") for i in iocs if i.get("malware_printable")}),
                "threat_types": list({i.get("threat_type", "") for i in iocs if i.get("threat_type")}),
                "confidence_avg": round(
                    sum(i.get("confidence_level", 0) for i in iocs) / max(len(iocs), 1), 1
                ),
            }
    except Exception as exc:
        logger.debug("[beaconing] ThreatFox lookup %s: %s", ip, exc)
    return None


def _resolve_ips(domain: str, subdomains: list[str]) -> dict[str, str]:
    """Резолвит домен и субдомены. Возвращает {ip: hostname}."""
    ip_map: dict[str, str] = {}
    targets = [domain] + subdomains

    socket.setdefaulttimeout(_DNS_TIMEOUT)
    try:
        for host in targets:
            try:
                results = socket.getaddrinfo(host, None)
                for r in results:
                    ip = r[4][0]
                    # Пропускаем IPv6 и loopback
                    if ":" in ip or ip.startswith("127.") or ip.startswith("10."):
                        continue
                    if ip not in ip_map:
                        ip_map[ip] = host
            except (socket.gaierror, socket.herror):
                pass
    finally:
        socket.setdefaulttimeout(None)

    logger.info("[beaconing] domain=%s резолвировано %d уникальных IP", domain, len(ip_map))
    return ip_map


def run_beaconing_detection(
    domain: str,
    core_api_url: str,
    internal_secret: str,
    subdomains: list[str] | None = None,
) -> dict[str, Any]:
    """
    Проверяет IP-адреса домена по репутационным фидам abuse.ch.

    Шаги:
      1. Резолвим IP для домена и субдоменов
      2. Проверяем каждый IP: Feodo Tracker (C2) + URLhaus + ThreatFox
      3. Найденные угрозы → event_type=malware_beaconing

    Возвращает: {"ips_checked": N, "threats_found": M, "sent": K}
    """
    domain = domain.strip().lower()
    logger.info("[beaconing] Начало проверки domain=%s", domain)

    # Загружаем Feodo фид
    feodo_ips = _load_feodo_feed()

    # Резолвим IP
    ip_map = _resolve_ips(domain, subdomains or [])
    if not ip_map:
        logger.info("[beaconing] domain=%s: IP не резолвируются, пропуск", domain)
        return {"ips_checked": 0, "threats_found": 0, "sent": 0}

    events: list[dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for ip, hostname in ip_map.items():
        threats: list[dict[str, Any]] = []

        # Проверка 1: Feodo Tracker (C2 ботнетов)
        if ip in feodo_ips:
            logger.warning("[beaconing] %s (%s) в Feodo Tracker C2!", hostname, ip)
            threats.append({
                "source": "feodo_tracker",
                "description": "IP в списке C2-серверов ботнетов (Emotet/QakBot/IcedID)",
                "severity": "critical",
            })

        # Проверка 2: URLhaus
        urlhaus_hit = _lookup_urlhaus(ip)
        if urlhaus_hit:
            logger.warning("[beaconing] %s (%s) в URLhaus: %s", hostname, ip, urlhaus_hit)
            threats.append({**urlhaus_hit, "severity": "high"})

        # Проверка 3: ThreatFox
        threatfox_hit = _lookup_threatfox(ip)
        if threatfox_hit:
            logger.warning("[beaconing] %s (%s) в ThreatFox: %s", hostname, ip, threatfox_hit)
            confidence = threatfox_hit.get("confidence_avg", 0)
            severity = "critical" if confidence >= 75 else "high" if confidence >= 50 else "medium"
            threats.append({**threatfox_hit, "severity": severity})

        if not threats:
            continue

        # Берём наивысший severity из всех угроз
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        top_sev = max(threats, key=lambda t: sev_order.get(t.get("severity", "info"), 0))["severity"]

        events.append({
            "event_type": "malware_beaconing",
            "severity": top_sev,
            "source_type": "scanner",
            "source_name": "beaconing_detector",
            "target_domain": domain,
            "payload": {
                "ip": ip,
                "hostname": hostname,
                "threats": threats,
                "feeds_matched": [t["source"] for t in threats],
            },
            "detected_at": now_iso,
        })

    sent = 0
    if events:
        result = bulk_ingest(events, core_api_url, internal_secret)
        sent = result.get("sent", 0)
        logger.info(
            "[beaconing] domain=%s threats=%d sent=%d",
            domain, len(events), sent,
        )

    logger.info(
        "[beaconing] Итого domain=%s ips_checked=%d threats_found=%d sent=%d",
        domain, len(ip_map), len(events), sent,
    )
    return {"ips_checked": len(ip_map), "threats_found": len(events), "sent": sent}
