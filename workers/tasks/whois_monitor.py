"""
Воркер WHOIS/Registrant Monitor — отслеживание изменений WHOIS-данных домена.

Использует протокол RDAP (Registration Data Access Protocol) — JSON-интерфейс
без дополнительных зависимостей, в отличие от классического WHOIS (порт 43).

Отслеживаемые поля:
  - registrant (имя/организация регистранта)
  - nameservers (список NS-серверов зоны)
  - expiry_date (дата истечения регистрации)

Baseline сохраняется как JSON в /tmp/whois_baseline_{domain_safe}.json.
Первый запуск — только сохраняет baseline, событий не генерирует.
"""
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

# Таймаут RDAP HTTP-запроса (секунды)
_RDAP_TIMEOUT = 10.0

# Порог «истекает скоро» — дней
_EXPIRY_CRITICAL_DAYS = 30
_EXPIRY_WARN_DAYS = 90

# Статусы успешной доставки
_INGEST_OK = frozenset({"accepted", "duplicate"})

# Основной RDAP-резолвер (универсальный, поддерживает большинство TLD)
_RDAP_PRIMARY = "https://rdap.org/domain/{domain}"

# Fallback только для .com зоны (официальный Verisign RDAP)
_RDAP_VERISIGN_COM = "https://rdap.verisign.com/com/v1/domain/{domain}"


# ──────────────────────────────────────────────────────────────────────────────
# Вспомогательные функции
# ──────────────────────────────────────────────────────────────────────────────

def _safe_domain_name(domain: str) -> str:
    """Превращает домен в безопасное имя файла: example.com → example_com."""
    return re.sub(r"[^a-z0-9_\-]", "_", domain.lower())


def _extract_registrant(entities: list[dict]) -> str | None:
    """
    Извлекает имя/организацию регистранта из массива entities RDAP-ответа.

    Ищет entity с ролью «registrant», затем парсит vcardArray.
    Возвращает строку «Имя / Организация» или None если не найдено.
    """
    for entity in entities:
        roles = entity.get("roles", [])
        if "registrant" not in roles:
            continue

        # vcardArray: ["vcard", [[имя, параметры, тип, значение], ...]]
        vcard_array = entity.get("vcardArray", [])
        if len(vcard_array) < 2:
            continue

        vcard_items = vcard_array[1]
        name = None
        org = None

        for item in vcard_items:
            if not isinstance(item, list) or len(item) < 4:
                continue
            field_name = item[0].lower() if item[0] else ""
            value = item[3] if item[3] else None

            if field_name == "fn":
                # «Formatted Name» — полное имя
                name = str(value).strip() if value else None
            elif field_name == "org":
                # Организация; может быть списком
                if isinstance(value, list):
                    org = str(value[0]).strip() if value else None
                else:
                    org = str(value).strip() if value else None

        # Возвращаем наиболее информативный идентификатор
        parts = [p for p in (name, org) if p and p.lower() not in ("", "redacted for privacy", "data redacted")]
        if parts:
            return " / ".join(dict.fromkeys(parts))  # дедупликация с сохранением порядка

        # Проверяем вложенные entities (регистраторы часто вкладывают данные)
        nested_entities = entity.get("entities", [])
        nested_result = _extract_registrant(nested_entities)
        if nested_result:
            return nested_result

    return None


def _extract_nameservers(rdap_data: dict) -> list[str]:
    """
    Извлекает список NS-серверов из RDAP-ответа.

    nameservers[].ldhName — буквенно-цифровое представление хоста (ASCII).
    """
    nameservers_raw = rdap_data.get("nameservers", [])
    result: list[str] = []
    for ns in nameservers_raw:
        ldh = ns.get("ldhName")
        if ldh:
            result.append(ldh.strip().lower().rstrip("."))
    return sorted(result)


def _extract_expiry_date(rdap_data: dict) -> str | None:
    """
    Извлекает дату истечения регистрации из массива events RDAP-ответа.

    Ищет событие с eventAction == "expiration".
    Возвращает ISO-8601 строку или None.
    """
    for event in rdap_data.get("events", []):
        if event.get("eventAction") == "expiration":
            return event.get("eventDate")
    return None


def _days_until_expiry(expiry_iso: str | None) -> int | None:
    """
    Вычисляет количество дней до истечения регистрации.

    Возвращает целое число (может быть отрицательным если уже истёк) или None.
    """
    if not expiry_iso:
        return None
    try:
        # RDAP возвращает ISO-8601, включая timezone offset
        # Поддерживаем форматы: 2025-12-31T00:00:00Z и 2025-12-31T00:00:00+00:00
        expiry_str = expiry_iso.replace("Z", "+00:00")
        expiry_dt = datetime.fromisoformat(expiry_str)
        if expiry_dt.tzinfo is None:
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return (expiry_dt - now).days
    except (ValueError, TypeError) as exc:
        logger.debug("[whois] Не удалось распарсить дату истечения '%s': %s", expiry_iso, exc)
        return None


# ──────────────────────────────────────────────────────────────────────────────
# RDAP запрос
# ──────────────────────────────────────────────────────────────────────────────

def fetch_whois_rdap(domain: str) -> dict[str, Any] | None:
    """
    Запрашивает RDAP и возвращает нормализованный dict с ключами:
      - registrant: str | None
      - nameservers: list[str]
      - expiry_date: str | None

    При ошибке возвращает None.
    Для .com доменов пробует Verisign RDAP как fallback.
    """
    domain = domain.strip().lower()
    urls_to_try: list[str] = [_RDAP_PRIMARY.format(domain=domain)]

    # Для .com доменов добавляем официальный Verisign RDAP как запасной вариант
    if domain.endswith(".com"):
        urls_to_try.append(_RDAP_VERISIGN_COM.format(domain=domain))

    for url in urls_to_try:
        try:
            logger.debug("[whois] RDAP запрос: %s", url)
            with httpx.Client(timeout=_RDAP_TIMEOUT, follow_redirects=True) as client:
                response = client.get(url, headers={"Accept": "application/rdap+json"})

            if response.status_code == 404:
                logger.debug("[whois] Домен не найден в RDAP: %s", domain)
                return None

            if response.status_code != 200:
                logger.debug("[whois] RDAP вернул %d для %s, пробуем следующий URL", response.status_code, domain)
                continue

            rdap_data = response.json()

            # Нормализуем в унифицированный формат для сравнения
            normalized: dict[str, Any] = {
                "registrant": _extract_registrant(rdap_data.get("entities", [])),
                "nameservers": _extract_nameservers(rdap_data),
                "expiry_date": _extract_expiry_date(rdap_data),
            }

            logger.debug(
                "[whois] %s: registrant=%s ns=%s expiry=%s",
                domain,
                normalized["registrant"],
                normalized["nameservers"],
                normalized["expiry_date"],
            )
            return normalized

        except httpx.TimeoutException:
            logger.warning("[whois] Таймаут RDAP запроса к %s", url)
            continue
        except httpx.RequestError as exc:
            logger.warning("[whois] Сетевая ошибка RDAP %s: %s", url, exc)
            continue
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("[whois] Не удалось распарсить RDAP-ответ от %s: %s", url, exc)
            continue
        except Exception as exc:
            logger.error("[whois] Неожиданная ошибка RDAP %s: %s", url, exc)
            continue

    logger.warning("[whois] Все RDAP-эндпоинты недоступны для %s", domain)
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Baseline — хранение и загрузка
# ──────────────────────────────────────────────────────────────────────────────

def _baseline_path(domain: str) -> Path:
    """Возвращает путь к файлу baseline для домена."""
    return Path(f"/tmp/whois_baseline_{_safe_domain_name(domain)}.json")


def load_baseline(domain: str) -> dict[str, Any] | None:
    """
    Загружает baseline из /tmp/whois_baseline_{safe_domain}.json.

    Возвращает dict с ключами registrant/nameservers/expiry_date или None если файл не найден.
    """
    path = _baseline_path(domain)
    if not path.exists():
        logger.debug("[whois] Baseline не найден для %s (%s)", domain, path)
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        logger.debug("[whois] Baseline загружен для %s", domain)
        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("[whois] Не удалось прочитать baseline %s: %s", path, exc)
        return None


def save_baseline(domain: str, data: dict[str, Any]) -> None:
    """
    Сохраняет baseline в /tmp/whois_baseline_{safe_domain}.json.

    Файл содержит нормализованные RDAP-данные + метаданные (когда сохранён).
    """
    path = _baseline_path(domain)
    payload = {
        **data,
        "_saved_at": datetime.now(timezone.utc).isoformat(),
        "_domain": domain,
    }
    try:
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("[whois] Baseline сохранён для %s → %s", domain, path)
    except OSError as exc:
        logger.error("[whois] Не удалось сохранить baseline для %s: %s", domain, exc)


# ──────────────────────────────────────────────────────────────────────────────
# Генерация событий
# ──────────────────────────────────────────────────────────────────────────────

def _build_events(
    domain: str,
    current: dict[str, Any],
    baseline: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Сравнивает текущие RDAP-данные с baseline и генерирует список событий.

    Возвращает список event-словарей, готовых для отправки через bulk_ingest.
    """
    events: list[dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    # ── Смена registrant ──────────────────────────────────────────────────────
    old_registrant = baseline.get("registrant")
    new_registrant = current.get("registrant")

    if old_registrant != new_registrant:
        logger.warning(
            "[whois] %s: смена registrant: '%s' → '%s'",
            domain, old_registrant, new_registrant,
        )
        events.append({
            "event_type": "asset_drift",
            "severity": "high",
            "source_type": "scanner",
            "source_name": "whois_monitor",
            "target_domain": domain,
            "payload": {
                "change": "registrant_changed",
                "description": f"Registrant домена {domain} изменился.",
                "old_registrant": old_registrant,
                "new_registrant": new_registrant,
            },
            "detected_at": now_iso,
        })

    # ── Смена nameservers ─────────────────────────────────────────────────────
    old_ns = baseline.get("nameservers", [])
    new_ns = current.get("nameservers", [])

    # Сравниваем отсортированные списки (порядок не важен, важен состав)
    if sorted(old_ns) != sorted(new_ns):
        added = sorted(set(new_ns) - set(old_ns))
        removed = sorted(set(old_ns) - set(new_ns))
        logger.warning(
            "[whois] %s: смена nameservers: добавлены=%s удалены=%s",
            domain, added, removed,
        )
        events.append({
            "event_type": "asset_drift",
            "severity": "high",
            "source_type": "scanner",
            "source_name": "whois_monitor",
            "target_domain": domain,
            "payload": {
                "change": "nameservers_changed",
                "description": f"Nameservers домена {domain} изменились.",
                "old_nameservers": old_ns,
                "new_nameservers": new_ns,
                "added": added,
                "removed": removed,
            },
            "detected_at": now_iso,
        })

    # ── Expiry date — проверка приближения истечения ──────────────────────────
    expiry_date = current.get("expiry_date")
    days = _days_until_expiry(expiry_date)

    if days is not None:
        if days < _EXPIRY_CRITICAL_DAYS:
            severity = "critical"
            description = (
                f"Домен {domain} истекает через {days} дн. ({expiry_date}). "
                "Требуется срочное продление."
            )
            logger.warning("[whois] %s: КРИТИЧНО — истекает через %d дн.", domain, days)
            events.append({
                "event_type": "asset_drift",
                "severity": severity,
                "source_type": "scanner",
                "source_name": "whois_monitor",
                "target_domain": domain,
                "payload": {
                    "change": "domain_expiring_critical",
                    "description": description,
                    "expiry_date": expiry_date,
                    "days_until_expiry": days,
                },
                "detected_at": now_iso,
            })
        elif days < _EXPIRY_WARN_DAYS:
            severity = "medium"
            description = (
                f"Домен {domain} истекает через {days} дн. ({expiry_date}). "
                "Рекомендуется продление."
            )
            logger.info("[whois] %s: предупреждение — истекает через %d дн.", domain, days)
            events.append({
                "event_type": "asset_drift",
                "severity": severity,
                "source_type": "scanner",
                "source_name": "whois_monitor",
                "target_domain": domain,
                "payload": {
                    "change": "domain_expiring_soon",
                    "description": description,
                    "expiry_date": expiry_date,
                    "days_until_expiry": days,
                },
                "detected_at": now_iso,
            })

    return events


# ──────────────────────────────────────────────────────────────────────────────
# Основная функция
# ──────────────────────────────────────────────────────────────────────────────

def check_whois(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, Any]:
    """
    Главная функция WHOIS/Registrant Monitor.

    Шаги:
    1. Запрашивает RDAP данные домена.
    2. При первом запуске сохраняет baseline и возвращает {"checked": True, "changes": 0, "sent": 0}.
    3. При последующих запусках сравнивает с baseline, генерирует события.
    4. Отправляет события через bulk_ingest, обновляет baseline.

    Возвращает: {"checked": True, "changes": N, "sent": M}
    """
    domain = domain.strip().lower()
    logger.info("[whois] Начало проверки domain=%s", domain)

    # ── Шаг 1: получить текущие RDAP данные ──────────────────────────────────
    current = fetch_whois_rdap(domain)
    if current is None:
        logger.warning("[whois] Не удалось получить RDAP-данные для %s", domain)
        return {"checked": False, "changes": 0, "sent": 0, "error": "rdap_unavailable"}

    # ── Шаг 2: загрузить baseline ─────────────────────────────────────────────
    baseline = load_baseline(domain)

    if baseline is None:
        # Первый запуск — сохраняем baseline, событий не генерируем
        logger.info("[whois] Первый запуск для %s — сохраняем baseline", domain)
        save_baseline(domain, current)
        return {"checked": True, "changes": 0, "sent": 0}

    # ── Шаг 3: сравнить и сгенерировать события ───────────────────────────────
    events = _build_events(domain, current, baseline)

    # ── Шаг 4: отправить события в Core API ───────────────────────────────────
    sent = 0
    if events:
        result = bulk_ingest(
            events=events,
            core_api_url=core_api_url,
            internal_secret=internal_secret,
        )
        sent = result.get("sent", 0)
        logger.info(
            "[whois] %s: изменений=%d отправлено=%d ошибок=%d",
            domain, len(events), sent, result.get("errors", 0),
        )

    # ── Шаг 5: обновить baseline актуальными данными ──────────────────────────
    save_baseline(domain, current)

    logger.info("[whois] Завершение проверки domain=%s changes=%d sent=%d", domain, len(events), sent)
    return {"checked": True, "changes": len(events), "sent": sent}
