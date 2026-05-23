"""
Воркер проверки email-адресов по базам утечек.

Источники:
  1. HaveIBeenPwned API v3 (с ключом или без — graceful degradation)
  2. LeakCheck public API (без ключа)

Паттерн использования:
  - check_email_hibp(email, api_key) → {"email", "breached", "breaches"}
  - check_email_leakcheck(email) → {"email", "found", "sources"}
  - check_domain_emails(domain, emails, core_api_url, internal_secret, hibp_key) → итоговая статистика
  - discover_and_check(domain, core_api_url, internal_secret, hibp_key) → авто-сбор + проверка
"""

import logging
import re
import time
from dataclasses import dataclass
from typing import Final

import httpx

logger = logging.getLogger(__name__)

# ── Константы ──────────────────────────────────────────────────────────────

# HIBP требует минимум 1.5 сек между запросами — иначе 429
HIBP_RATE_LIMIT_SECONDS: Final[float] = 1.5

# Таймаут HTTP-запроса в секундах
HTTP_TIMEOUT: Final[float] = 15.0

# User-Agent обязателен для HIBP API
USER_AGENT: Final[str] = "EASM-Platform/1.0"

# Базовые URL
HIBP_BASE_URL: Final[str] = "https://haveibeenpwned.com/api/v3"
LEAKCHECK_BASE_URL: Final[str] = "https://leakcheck.io/api/public"

# Типичные email-паттерны для домена
COMMON_EMAIL_PREFIXES: Final[tuple[str, ...]] = (
    "admin",
    "info",
    "support",
    "security",
    "webmaster",
    "contact",
    "hello",
    "noreply",
    "postmaster",
    "abuse",
)

# Regex для валидации email
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


# ── Вспомогательные структуры ──────────────────────────────────────────────

@dataclass
class CheckStats:
    """Накапливаемая статистика проверки."""
    checked: int = 0
    breached: int = 0
    sent: int = 0
    errors: int = 0

    def to_dict(self) -> dict:
        return {
            "checked": self.checked,
            "breached": self.breached,
            "sent": self.sent,
            "errors": self.errors,
        }


# ── Вспомогательные функции ────────────────────────────────────────────────

def _build_hibp_headers(api_key: str) -> dict[str, str]:
    """Формирует заголовки для HIBP API."""
    headers: dict[str, str] = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    if api_key:
        headers["hibp-api-key"] = api_key
    return headers


def _is_valid_email(email: str) -> bool:
    """Базовая валидация формата email."""
    return bool(_EMAIL_RE.match(email.strip()))


def _extract_emails_from_payload(payload: dict, domain: str) -> list[str]:
    """
    Извлекает email-адреса из payload события,
    фильтрует только те, что принадлежат целевому домену.
    """
    emails: list[str] = []
    suffix = f"@{domain.lower()}"

    def _walk(obj: object, depth: int = 0) -> None:
        # Защита от бесконечной рекурсии при аномально вложенных payload
        if depth > 10:
            return
        if isinstance(obj, str):
            if "@" in obj and obj.lower().endswith(suffix) and _is_valid_email(obj):
                emails.append(obj.lower())
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v, depth + 1)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                _walk(item, depth + 1)

    _walk(payload)
    return emails


def _send_breach_event(
    *,
    ingest_url: str,
    headers_ingest: dict[str, str],
    domain: str,
    email: str,
    breach_count: int,
    breach_names: list[str],
    source: str,
    stats: CheckStats,
) -> None:
    """
    Отправляет событие email_breach в Core API.
    Обновляет счётчики stats.sent / stats.errors на месте.
    """
    # event_type="email_breach" и source_type="breach_checker" зарегистрированы
    # в NormalizedEvent (EventType.EMAIL_BREACH, SourceType.BREACH_CHECKER).
    event = {
        "event_type": "email_breach",
        "severity": "high",
        "source_type": "breach_checker",
        "source_name": source,
        "target_domain": domain,
        "payload": {
            "email": email,
            "breach_count": breach_count,
            "breach_names": breach_names,
            "source": source,
        },
    }
    try:
        resp = httpx.post(ingest_url, json=event, headers=headers_ingest, timeout=HTTP_TIMEOUT)
        status_val = resp.json().get("status", "error")
        if status_val in ("accepted", "duplicate"):
            stats.sent += 1
        else:
            logger.warning("[breach] ingest вернул неожиданный статус: %s", status_val)
            stats.errors += 1
    except Exception as exc:
        logger.error("[breach] Ошибка отправки события для %s: %s", email, exc)
        stats.errors += 1


# ── Публичные функции ──────────────────────────────────────────────────────

def check_email_hibp(email: str, api_key: str = "") -> dict:
    """
    Проверяет email через HaveIBeenPwned API v3.

    Возвращает:
      {
        "email": "...",
        "breached": True/False,
        "breaches": ["Adobe", "LinkedIn", ...],
        "error": None | "unauthorized" | "rate_limit" | "network_error"
      }

    Особые случаи:
      - 401 (нет ключа или неверный) → breached=False, error="unauthorized"
      - 429 (rate limit) → breached=False, error="rate_limit"
      - 404 → breached=False (чисто)
      - Сетевая ошибка → breached=False, error="network_error"
    """
    url = f"{HIBP_BASE_URL}/breachedaccount/{email}"
    params = {"truncateResponse": "false"}
    headers = _build_hibp_headers(api_key)

    try:
        resp = httpx.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
    except Exception as exc:
        logger.warning("[hibp] Сетевая ошибка для %s: %s", email, exc)
        return {"email": email, "breached": False, "breaches": [], "error": "network_error"}

    if resp.status_code == 404:
        # Email не найден в базах — это норма
        return {"email": email, "breached": False, "breaches": [], "error": None}

    if resp.status_code == 401:
        # API-ключ не предоставлен или неверен
        logger.warning("[hibp] 401 для %s — ключ HIBP отсутствует или невалиден", email)
        return {"email": email, "breached": False, "breaches": [], "error": "unauthorized"}

    if resp.status_code == 429:
        logger.warning("[hibp] 429 rate limit для %s", email)
        return {"email": email, "breached": False, "breaches": [], "error": "rate_limit"}

    if resp.status_code != 200:
        logger.warning("[hibp] Неожиданный статус %d для %s", resp.status_code, email)
        return {"email": email, "breached": False, "breaches": [], "error": f"http_{resp.status_code}"}

    try:
        data = resp.json()
    except Exception:
        logger.warning("[hibp] Не удалось разобрать JSON ответ для %s", email)
        return {"email": email, "breached": False, "breaches": [], "error": "parse_error"}

    # HIBP v3 возвращает список объектов с полем "Name"
    if not isinstance(data, list):
        return {"email": email, "breached": False, "breaches": [], "error": "unexpected_format"}

    breach_names = [b.get("Name", "") for b in data if isinstance(b, dict)]
    return {
        "email": email,
        "breached": bool(breach_names),
        "breaches": breach_names,
        "error": None,
    }


def check_email_leakcheck(email: str) -> dict:
    """
    Проверяет email через LeakCheck public API (без ключа).

    Возвращает:
      {
        "email": "...",
        "found": N,
        "sources": [...],
        "error": None | "network_error" | "api_error"
      }
    """
    params = {"check": email}
    try:
        resp = httpx.get(
            LEAKCHECK_BASE_URL,
            params=params,
            headers={"User-Agent": USER_AGENT},
            timeout=HTTP_TIMEOUT,
        )
    except Exception as exc:
        logger.warning("[leakcheck] Сетевая ошибка для %s: %s", email, exc)
        return {"email": email, "found": 0, "sources": [], "error": "network_error"}

    if resp.status_code != 200:
        logger.warning("[leakcheck] Статус %d для %s", resp.status_code, email)
        return {"email": email, "found": 0, "sources": [], "error": f"http_{resp.status_code}"}

    try:
        data = resp.json()
    except Exception:
        logger.warning("[leakcheck] Не удалось разобрать JSON для %s", email)
        return {"email": email, "found": 0, "sources": [], "error": "parse_error"}

    if not data.get("success", False):
        # API вернул ошибку (например, слишком частые запросы)
        error_msg = data.get("error", "api_error")
        logger.warning("[leakcheck] API вернул success=false для %s: %s", email, error_msg)
        return {"email": email, "found": 0, "sources": [], "error": error_msg}

    found = data.get("found", 0)
    sources = data.get("sources", [])
    return {"email": email, "found": found, "sources": sources, "error": None}


def check_domain_emails(
    domain: str,
    emails: list[str],
    core_api_url: str,
    internal_secret: str,
    hibp_key: str = "",
) -> dict:
    """
    Проверяет список email-адресов через HIBP и LeakCheck.
    При нахождении утечки отправляет событие email_breach в Core API.

    Rate limit соблюдается автоматически (1.5 сек между HIBP-запросами).

    Возвращает: {"checked": N, "breached": M, "sent": K, "errors": E}
    """
    if not emails:
        logger.info("[breach] Пустой список email для домена %s", domain)
        return {"checked": 0, "breached": 0, "sent": 0, "errors": 0}

    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    headers_ingest = {"Authorization": f"Bearer {internal_secret}"}
    stats = CheckStats()

    # Дедупликация входного списка с сохранением порядка
    seen: set[str] = set()
    unique_emails: list[str] = []
    for e in emails:
        normalized = e.strip().lower()
        if normalized and normalized not in seen and _is_valid_email(normalized):
            seen.add(normalized)
            unique_emails.append(normalized)

    logger.info("[breach] Запуск проверки %d email для домена %s", len(unique_emails), domain)

    for email in unique_emails:
        stats.checked += 1

        # ── HIBP ──────────────────────────────────────────────────────
        hibp_result = check_email_hibp(email, hibp_key)

        # Обязательная пауза после каждого HIBP-запроса
        time.sleep(HIBP_RATE_LIMIT_SECONDS)

        if hibp_result.get("error") == "rate_limit":
            # При превышении лимита — дополнительная пауза и повтор
            logger.warning("[hibp] Rate limit — пауза 10 сек, повтор для %s", email)
            time.sleep(10.0)
            hibp_result = check_email_hibp(email, hibp_key)
            time.sleep(HIBP_RATE_LIMIT_SECONDS)

        if hibp_result.get("error") not in (None, "unauthorized", "rate_limit"):
            stats.errors += 1

        if hibp_result.get("breached"):
            stats.breached += 1
            _send_breach_event(
                ingest_url=ingest_url,
                headers_ingest=headers_ingest,
                domain=domain,
                email=email,
                breach_count=len(hibp_result["breaches"]),
                breach_names=hibp_result["breaches"],
                source="hibp",
                stats=stats,
            )

        # ── LeakCheck ─────────────────────────────────────────────────
        lc_result = check_email_leakcheck(email)

        if lc_result.get("error") and lc_result["error"] != "api_error":
            stats.errors += 1

        if lc_result.get("found", 0) > 0:
            # Не засчитываем дважды, если HIBP уже нашёл
            if not hibp_result.get("breached"):
                stats.breached += 1
            _send_breach_event(
                ingest_url=ingest_url,
                headers_ingest=headers_ingest,
                domain=domain,
                email=email,
                breach_count=lc_result["found"],
                breach_names=lc_result.get("sources", []),
                source="leakcheck",
                stats=stats,
            )

        logger.debug(
            "[breach] %s — HIBP: breached=%s, LeakCheck: found=%d",
            email,
            hibp_result.get("breached"),
            lc_result.get("found", 0),
        )

    result = stats.to_dict()
    logger.info(
        "[breach] domain=%s checked=%d breached=%d sent=%d errors=%d",
        domain,
        result["checked"],
        result["breached"],
        result["sent"],
        result["errors"],
    )
    return result


def _collect_emails_from_core(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> list[str]:
    """
    Собирает email-адреса домена из уже сохранённых stealer_log событий через Core API.
    Использует публичный /events/ эндпоинт с фильтром по event_type.

    Возвращает список найденных email-адресов.
    """
    # GET /api/v1/events/ требует JWT, но воркер имеет только internal_secret.
    # Используем internal_secret как Authorization для внутреннего доступа.
    # На практике этот эндпоинт может быть закрыт — обрабатываем gracefully.
    events_url = f"{core_api_url}/api/v1/events/"
    params = {"event_type": "stealer_log", "domain": domain, "limit": 200}
    headers = {"Authorization": f"Bearer {internal_secret}"}

    emails: list[str] = []
    suffix = f"@{domain.lower()}"

    try:
        resp = httpx.get(events_url, params=params, headers=headers, timeout=HTTP_TIMEOUT)
        if resp.status_code != 200:
            logger.debug(
                "[breach] Не удалось получить события stealer_log: HTTP %d", resp.status_code
            )
            return emails

        events = resp.json()
        if not isinstance(events, list):
            return emails

        for event in events:
            payload = event.get("payload", {})
            extracted = _extract_emails_from_payload(payload, domain)
            emails.extend(extracted)

    except Exception as exc:
        logger.debug("[breach] Ошибка при сборе email из событий: %s", exc)

    return emails


def discover_and_check(
    domain: str,
    core_api_url: str,
    internal_secret: str,
    hibp_key: str = "",
) -> dict:
    """
    Авто-обнаружение email-адресов домена + проверка по базам утечек.

    Источники email:
      1. Stealer-log события из Core API (реальные скомпрометированные адреса)
      2. Типичные паттерны: admin@, info@, support@, ... (покрытие без логов)

    Возвращает: {"emails_discovered": N, "checked": M, "breached": K, "sent": J, "errors": E}
    """
    domain = domain.strip().lower()
    logger.info("[breach] Авто-обнаружение email для домена %s", domain)

    # Источник 1: из stealer-log событий
    discovered_from_logs = _collect_emails_from_core(domain, core_api_url, internal_secret)
    logger.info("[breach] Найдено в stealer-логах: %d email", len(discovered_from_logs))

    # Источник 2: типичные паттерны
    pattern_emails = [f"{prefix}@{domain}" for prefix in COMMON_EMAIL_PREFIXES]

    # Объединяем, дедупликация произойдёт внутри check_domain_emails
    all_emails = discovered_from_logs + pattern_emails
    emails_discovered = len(set(e.lower() for e in all_emails if _is_valid_email(e)))

    result = check_domain_emails(
        domain=domain,
        emails=all_emails,
        core_api_url=core_api_url,
        internal_secret=internal_secret,
        hibp_key=hibp_key,
    )

    return {
        "emails_discovered": emails_discovered,
        **result,
    }
