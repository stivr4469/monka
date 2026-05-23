"""
Автоматические источники стилер-логов.

Запрашивает публичные OSINT-API и собирает скомпрометированные
учётные данные для мониторимого домена.

Источники:
  1. Hudson Rock Cavalier  — бесплатный OSINT API, без ключа
  2. Snusbase              — требует SNUSBASE_API_KEY
  3. LeakCheck             — требует LEAKCHECK_API_KEY

Пароли хранятся как есть — инструмент OSINT, не менеджер паролей.
"""
import logging
import os
import time
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = 20
_CACHE: dict[str, tuple[float, list[dict]]] = {}
_CACHE_TTL = 3600  # 1 час


# ─────────────────────────────────────────────────────────
# Утилиты
# ─────────────────────────────────────────────────────────

def _cached(key: str) -> list[dict] | None:
    if key in _CACHE:
        ts, data = _CACHE[key]
        if time.time() - ts < _CACHE_TTL:
            return data
    return None


def _store(key: str, data: list[dict]) -> None:
    _CACHE[key] = (time.time(), data)


def _send_events(
    records: list[dict],
    source_name: str,
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> tuple[int, int]:
    """Отправляет записи в Core API. Возвращает (sent, errors)."""
    url = f"{core_api_url}/api/v1/internal/ingest"
    headers = {"Authorization": f"Bearer {internal_secret}"}
    sent = errors = 0

    for rec in records:
        event = {
            "event_type": "stealer_log",
            "severity": "critical",
            "source_type": "stealer_source",
            "source_name": source_name,
            "target_domain": domain,
            "payload": rec,
        }
        try:
            r = httpx.post(url, json=event, headers=headers, timeout=10)
            status = r.json().get("status", "error")
            if status in ("accepted", "duplicate"):
                sent += 1
            else:
                errors += 1
        except Exception as exc:
            logger.error("[%s] ingest error: %s", source_name, exc)
            errors += 1

    return sent, errors


# ─────────────────────────────────────────────────────────
# 1. Hudson Rock Cavalier (бесплатно, без ключа)
# ─────────────────────────────────────────────────────────

def _query_hudsonrock(domain: str) -> list[dict]:
    """
    GET https://cavalier.hudsonrock.com/api/json/v2/osint-tools/employees-and-users
    Возвращает список записей {url, login, password, stealer_type, date_compromised}
    """
    key = f"hudsonrock:{domain}"
    if cached := _cached(key):
        return cached

    try:
        r = httpx.get(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/employees-and-users",
            params={"domain": domain},
            timeout=_TIMEOUT,
            headers={"User-Agent": "EASM-Monitor/1.0"},
        )
        if r.status_code != 200:
            logger.warning("[hudsonrock] HTTP %d для %s", r.status_code, domain)
            return []

        data = r.json()
        records = []

        for group in ("employees", "users"):
            for item in data.get("data", {}).get(group, []):
                records.append({
                    "url": item.get("url", ""),
                    "login": item.get("username", ""),
                    "password": item.get("password", ""),
                    "stealer_type": item.get("stealer_type", "unknown"),
                    "date_compromised": item.get("date_compromised", ""),
                    "computer_name": item.get("computer_name", ""),
                    "source_group": group,
                })

        logger.info("[hudsonrock] %s: %d записей", domain, len(records))
        _store(key, records)
        return records

    except Exception as exc:
        logger.error("[hudsonrock] ошибка для %s: %s", domain, exc)
        return []


# ─────────────────────────────────────────────────────────
# 2. Snusbase (требует API-ключ)
# ─────────────────────────────────────────────────────────

def _query_snusbase(domain: str, api_key: str) -> list[dict]:
    """
    POST https://api.snusbase.com/data/search
    Ищет по email-домену. Требует SNUSBASE_API_KEY.
    """
    key = f"snusbase:{domain}"
    if cached := _cached(key):
        return cached

    try:
        r = httpx.post(
            "https://api.snusbase.com/data/search",
            json={"terms": [domain], "types": ["email"], "wildcard": True},
            headers={
                "Auth": api_key,
                "Content-Type": "application/json",
            },
            timeout=_TIMEOUT,
        )
        if r.status_code != 200:
            logger.warning("[snusbase] HTTP %d для %s", r.status_code, domain)
            return []

        records = []
        for dataset, entries in r.json().get("results", {}).items():
            for entry in entries:
                email = entry.get("email", "")
                if not email.lower().endswith(f"@{domain}"):
                    continue
                records.append({
                    "url": "",
                    "login": email,
                    "password": entry.get("password", ""),
                    "hash": entry.get("hash", ""),
                    "dataset": dataset,
                    "name": entry.get("name", ""),
                })

        logger.info("[snusbase] %s: %d записей", domain, len(records))
        _store(key, records)
        return records

    except Exception as exc:
        logger.error("[snusbase] ошибка для %s: %s", domain, exc)
        return []


# ─────────────────────────────────────────────────────────
# 3. LeakCheck (требует API-ключ)
# ─────────────────────────────────────────────────────────

def _query_leakcheck(domain: str, api_key: str) -> list[dict]:
    """
    GET https://leakcheck.io/api/v2/query/{domain}?type=domain
    Требует LEAKCHECK_API_KEY.
    """
    key = f"leakcheck:{domain}"
    if cached := _cached(key):
        return cached

    try:
        r = httpx.get(
            f"https://leakcheck.io/api/v2/query/{domain}",
            params={"type": "domain"},
            headers={
                "X-API-Key": api_key,
                "User-Agent": "EASM-Monitor/1.0",
            },
            timeout=_TIMEOUT,
        )
        if r.status_code == 402:
            logger.warning("[leakcheck] Лимит запросов исчерпан")
            return []
        if r.status_code != 200:
            logger.warning("[leakcheck] HTTP %d для %s", r.status_code, domain)
            return []

        records = []
        for entry in r.json().get("result", []):
            records.append({
                "url": "",
                "login": entry.get("email", entry.get("username", "")),
                "password": entry.get("password", ""),
                "hash": entry.get("hash", ""),
                "sources": entry.get("sources", []),
            })

        logger.info("[leakcheck] %s: %d записей", domain, len(records))
        _store(key, records)
        return records

    except Exception as exc:
        logger.error("[leakcheck] ошибка для %s: %s", domain, exc)
        return []


# ─────────────────────────────────────────────────────────
# Оркестратор
# ─────────────────────────────────────────────────────────

def query_stealer_sources(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict:
    """
    Опрашивает все доступные источники для домена и ингестит результаты.

    Возвращает сводку: {source: {found, sent, errors}, ...}
    """
    snusbase_key = os.getenv("SNUSBASE_API_KEY", "")
    leakcheck_key = os.getenv("LEAKCHECK_API_KEY", "")

    summary: dict[str, dict] = {}

    # ── Hudson Rock (всегда)
    hr_records = _query_hudsonrock(domain)
    hr_sent, hr_errors = _send_events(
        hr_records, "hudsonrock-cavalier", domain, core_api_url, internal_secret
    )
    summary["hudsonrock"] = {
        "found": len(hr_records),
        "sent": hr_sent,
        "errors": hr_errors,
    }

    # ── Snusbase (если есть ключ)
    if snusbase_key:
        sb_records = _query_snusbase(domain, snusbase_key)
        sb_sent, sb_errors = _send_events(
            sb_records, "snusbase", domain, core_api_url, internal_secret
        )
        summary["snusbase"] = {
            "found": len(sb_records),
            "sent": sb_sent,
            "errors": sb_errors,
        }
    else:
        summary["snusbase"] = {"found": 0, "sent": 0, "errors": 0, "skip": "нет SNUSBASE_API_KEY"}

    # ── LeakCheck (если есть ключ)
    if leakcheck_key:
        lc_records = _query_leakcheck(domain, leakcheck_key)
        lc_sent, lc_errors = _send_events(
            lc_records, "leakcheck", domain, core_api_url, internal_secret
        )
        summary["leakcheck"] = {
            "found": len(lc_records),
            "sent": lc_sent,
            "errors": lc_errors,
        }
    else:
        summary["leakcheck"] = {"found": 0, "sent": 0, "errors": 0, "skip": "нет LEAKCHECK_API_KEY"}

    total_found = sum(v["found"] for v in summary.values())
    total_sent = sum(v["sent"] for v in summary.values())
    logger.info(
        "[stealer_sources] %s: найдено=%d отправлено=%d",
        domain, total_found, total_sent,
    )
    return summary
