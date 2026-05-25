"""
BGP/ASN мониторинг — детекция смены провайдера и IP-диапазонов.
Использует BGPView API (bgpview.io) — бесплатный, без ключей.
"""
import ipaddress
import json
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

_BGP_API = "https://api.bgpview.io"
_TIMEOUT = 20.0
_BASELINE_DIR = Path("/tmp")
_HTTP_TIMEOUT = httpx.Timeout(20.0)


# ─────────────────────────────────────────────────────────────────────────────
# DNS и IP-утилиты
# ─────────────────────────────────────────────────────────────────────────────

def resolve_ips(domain: str) -> list[str]:
    """DNS резолв домена → список публичных IPv4."""
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = list({r[4][0] for r in results})
        return [ip for ip in ips if not _is_private(ip)]
    except (socket.gaierror, OSError):
        return []


def _is_private(ip: str) -> bool:
    """Проверяет RFC 1918 / loopback / link-local."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# BGPView API
# ─────────────────────────────────────────────────────────────────────────────

def get_ip_info(ip: str) -> dict[str, Any] | None:
    """
    GET https://api.bgpview.io/ip/{ip}

    Возвращает: {"asn": 13335, "as_name": "CLOUDFLARENET", "prefix": "1.1.1.0/24", "country": "US"}
    При ошибке или отсутствии данных возвращает None.
    """
    try:
        resp = httpx.get(f"{_BGP_API}/ip/{ip}", timeout=_HTTP_TIMEOUT)
        if resp.status_code != 200:
            return None
        data = resp.json()
        # data["data"]["prefixes"][0] содержит asn, as_name, prefix, country_code
        prefixes = data.get("data", {}).get("prefixes", [])
        if not prefixes:
            return None
        prefix = prefixes[0]
        return {
            "asn": prefix.get("asn", {}).get("asn"),
            "as_name": prefix.get("asn", {}).get("name", ""),
            "prefix": prefix.get("prefix", ""),
            "country": prefix.get("country_code", ""),
        }
    except Exception as exc:
        logger.warning("[bgp] get_ip_info error for %s: %s", ip, exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Baseline — хранение и загрузка
# ─────────────────────────────────────────────────────────────────────────────

def _baseline_path(domain: str) -> Path:
    safe = domain.replace(".", "_").replace("/", "_")
    return _BASELINE_DIR / f"bgp_baseline_{safe}.json"


def load_baseline(domain: str) -> dict[str, Any] | None:
    """
    Загружает baseline из файла.
    Структура: {"ip": {"asn": N, "as_name": "...", "prefix": "...", "country": "..."}, ...}
    Возвращает None если файл не найден.
    """
    path = _baseline_path(domain)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("[bgp] Не удалось прочитать baseline для %s: %s", domain, exc)
        return None


def save_baseline(domain: str, data: dict[str, Any]) -> None:
    """Сохраняет baseline в JSON-файл."""
    try:
        _baseline_path(domain).write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.debug("[bgp] Baseline сохранён для %s", domain)
    except OSError as exc:
        logger.error("[bgp] Не удалось сохранить baseline для %s: %s", domain, exc)


# ─────────────────────────────────────────────────────────────────────────────
# Генерация событий
# ─────────────────────────────────────────────────────────────────────────────

def _build_events(
    domain: str,
    ip: str,
    old_info: dict[str, Any],
    new_info: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Сравнивает старые и новые BGP-данные для одного IP, генерирует события.

    Правила:
    - Смена ASN → severity=high (смена провайдера)
    - Смена prefix → severity=medium (смена IP-блока)
    """
    events: list[dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    # ── Смена ASN ──────────────────────────────────────────────────────────────
    old_asn = old_info.get("asn")
    new_asn = new_info.get("asn")
    if old_asn != new_asn:
        logger.warning(
            "[bgp] %s (%s): смена ASN %s → %s (%s)",
            domain, ip, old_asn, new_asn, new_info.get("as_name", ""),
        )
        events.append({
            "event_type": "asset_change",
            "severity": "high",
            "source_type": "scanner",
            "source_name": "bgp_monitor",
            "target_domain": domain,
            "payload": {
                "change": "asn",
                "ip": ip,
                "old_asn": old_asn,
                "new_asn": new_asn,
                "as_name": new_info.get("as_name", ""),
                "description": (
                    f"Домен {domain} сменил провайдера: AS{old_asn} → AS{new_asn} "
                    f"({new_info.get('as_name', '')})"
                ),
            },
            "detected_at": now_iso,
        })

    # ── Смена prefix ──────────────────────────────────────────────────────────
    old_prefix = old_info.get("prefix")
    new_prefix = new_info.get("prefix")
    if old_prefix != new_prefix and old_asn == new_asn:
        # Только если ASN не изменился — иначе дублируем информацию из ASN-события
        logger.info(
            "[bgp] %s (%s): смена prefix %s → %s",
            domain, ip, old_prefix, new_prefix,
        )
        events.append({
            "event_type": "asset_change",
            "severity": "medium",
            "source_type": "scanner",
            "source_name": "bgp_monitor",
            "target_domain": domain,
            "payload": {
                "change": "ip_prefix",
                "ip": ip,
                "old_prefix": old_prefix,
                "new_prefix": new_prefix,
                "asn": new_asn,
                "as_name": new_info.get("as_name", ""),
                "description": (
                    f"IP-блок домена {domain} изменился: {old_prefix} → {new_prefix}"
                ),
            },
            "detected_at": now_iso,
        })

    return events


# ─────────────────────────────────────────────────────────────────────────────
# Основная функция
# ─────────────────────────────────────────────────────────────────────────────

def check_bgp(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, Any]:
    """
    Основная функция мониторинга BGP/ASN.

    1. Резолвим IP домена
    2. Получаем ASN/prefix для каждого IP
    3. Сравниваем с baseline
    4. Генерируем события при изменениях:
       - Смена AS → severity=high (смена провайдера)
       - Смена /prefix → severity=medium (смена IP-блока)
       - Новый IP → severity=low
    5. Сохраняем новый baseline

    Returns: {"checked": N, "changes": N, "sent": N}
    """
    domain = domain.strip().lower()
    logger.info("[bgp] Начало проверки domain=%s", domain)

    # ── Шаг 1: резолвим IP ────────────────────────────────────────────────────
    ips = resolve_ips(domain)
    if not ips:
        logger.warning("[bgp] Не удалось получить IP для %s", domain)
        return {"checked": 0, "changes": 0, "sent": 0, "error": "no_ips"}

    # ── Шаг 2: получаем ASN/prefix для каждого IP ────────────────────────────
    current_snapshot: dict[str, Any] = {}
    for ip in ips:
        info = get_ip_info(ip)
        if info is not None:
            current_snapshot[ip] = info
        else:
            logger.debug("[bgp] Не удалось получить BGP-данные для IP %s", ip)

    # ── Шаг 3: загружаем baseline ─────────────────────────────────────────────
    baseline = load_baseline(domain)
    if baseline is None:
        # Первый запуск — сохраняем baseline, событий не генерируем
        logger.info("[bgp] Первый запуск для %s — сохраняем baseline (%d IP)", domain, len(current_snapshot))
        save_baseline(domain, current_snapshot)
        return {"checked": len(current_snapshot), "changes": 0, "sent": 0}

    # ── Шаг 4: сравниваем и генерируем события ───────────────────────────────
    all_events: list[dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for ip, new_info in current_snapshot.items():
        if ip not in baseline:
            # Новый IP — severity=low
            logger.info("[bgp] %s: новый IP %s (AS%s)", domain, ip, new_info.get("asn"))
            all_events.append({
                "event_type": "asset_change",
                "severity": "low",
                "source_type": "scanner",
                "source_name": "bgp_monitor",
                "target_domain": domain,
                "payload": {
                    "change": "new_ip",
                    "ip": ip,
                    "asn": new_info.get("asn"),
                    "as_name": new_info.get("as_name", ""),
                    "prefix": new_info.get("prefix", ""),
                    "description": f"Новый IP {ip} обнаружен для домена {domain}",
                },
                "detected_at": now_iso,
            })
        else:
            # IP уже был в baseline — сравниваем ASN/prefix
            old_info = baseline[ip]
            events = _build_events(domain, ip, old_info, new_info)
            all_events.extend(events)

    # ── Шаг 5: отправляем события ─────────────────────────────────────────────
    sent = 0
    if all_events:
        result = bulk_ingest(
            events=all_events,
            core_api_url=core_api_url,
            internal_secret=internal_secret,
        )
        sent = result.get("sent", 0)
        logger.info(
            "[bgp] %s: изменений=%d отправлено=%d ошибок=%d",
            domain, len(all_events), sent, result.get("errors", 0),
        )

    # ── Шаг 6: обновляем baseline ─────────────────────────────────────────────
    save_baseline(domain, current_snapshot)

    logger.info(
        "[bgp] Завершение проверки domain=%s checked=%d changes=%d sent=%d",
        domain, len(current_snapshot), len(all_events), sent,
    )
    return {"checked": len(current_snapshot), "changes": len(all_events), "sent": sent}
