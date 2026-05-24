"""
Интеграция с IntelX.io API для поиска утечек по домену.

IntelX (Intelligence X) — поисковик по даркнету, утечкам и архивам.
Документация: https://intelx.io/product?tab=developer
Публичный API: https://2.intelx.io (без ключа — режим phonebook)

Принципы:
  - Без Tor, clearnet запросы
  - Таймаут 10с
  - Без API-ключа работает phonebook-режим (лимит: 5 результатов)
  - shell=False везде
  - Graceful degradation: при ошибке API — логируем и возвращаем пустой результат
"""
import logging
import time
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# Базовый URL публичного IntelX API
_INTELX_API_BASE = "https://2.intelx.io"

# Таймаут clearnet-запросов
_HTTP_TIMEOUT = 10.0

# User-Agent для запросов
_USER_AGENT = (
    "Mozilla/5.0 (compatible; EASM-DarknetMonitor/1.0; +https://github.com/easm)"
)

# Максимум результатов для публичного API (без ключа)
_PUBLIC_API_MAX_RESULTS = 5

# Пауза между запросами API в секундах (уважаем rate limit)
_REQUEST_DELAY = 2.0

# Типы результатов IntelX, которые нас интересуют
# Полный список: https://intelx.io/product?tab=developer#types
_RELEVANT_TYPES: frozenset[int] = frozenset({
    1,   # email
    2,   # domain
    3,   # URL
    4,   # IP-адрес
    7,   # пароль (если связан с нашим доменом)
    13,  # логин
})

# Соответствие кодов типов человекочитаемым именам
_TYPE_NAMES: dict[int, str] = {
    1: "email",
    2: "domain",
    3: "url",
    4: "ip",
    7: "password",
    13: "login",
    0: "unknown",
}


def _make_headers(api_key: Optional[str] = None) -> dict[str, str]:
    """Формирует заголовки запроса. С ключом — авторизованный режим."""
    headers = {
        "User-Agent": _USER_AGENT,
        "Accept": "application/json",
    }
    if api_key:
        headers["x-key"] = api_key
    return headers


def _search_phonebook(
    domain: str,
    api_key: Optional[str] = None,
) -> list[dict[str, Any]]:
    """
    Ищет домен через phonebook-эндпоинт IntelX.

    Phonebook-режим — упрощённый поиск, доступен без ключа.
    Возвращает email-адреса, домены и URL, связанные с целевым доменом.

    Возвращает:
        list[dict] — каждый элемент: {type, value, date}
        [] при ошибке или пустом результате
    """
    results: list[dict[str, Any]] = []

    try:
        # Шаг 1: инициируем поиск, получаем id задачи
        search_payload = {
            "term": domain,
            "maxresults": _PUBLIC_API_MAX_RESULTS,
            "media": 0,   # все типы медиа
            "target": 0,  # phonebook
            "terminate": [],
            "timeout": 5,
        }

        response = httpx.post(
            f"{_INTELX_API_BASE}/phonebook/search",
            json=search_payload,
            headers=_make_headers(api_key),
            timeout=_HTTP_TIMEOUT,
        )

        if response.status_code == 402:
            logger.warning("[intelx] Лимит запросов IntelX исчерпан (402 Payment Required)")
            return []

        if response.status_code != 200:
            logger.warning("[intelx] HTTP %d при инициации поиска", response.status_code)
            return []

        search_data = response.json()
        task_id: str = search_data.get("id", "")

        if not task_id:
            logger.warning("[intelx] Не получен task_id от /phonebook/search")
            return []

        logger.info("[intelx] Phonebook search task_id=%s для domain=%s", task_id, domain)

        # Небольшая пауза — даём IntelX собрать результаты
        time.sleep(_REQUEST_DELAY)

        # Шаг 2: получаем результаты по task_id
        result_response = httpx.get(
            f"{_INTELX_API_BASE}/phonebook/search/result",
            params={
                "id": task_id,
                "limit": _PUBLIC_API_MAX_RESULTS,
                "offset": 0,
            },
            headers=_make_headers(api_key),
            timeout=_HTTP_TIMEOUT,
        )

        if result_response.status_code != 200:
            logger.warning(
                "[intelx] HTTP %d при получении результатов (task_id=%s)",
                result_response.status_code,
                task_id,
            )
            return []

        result_data = result_response.json()
        selectors: list[dict[str, Any]] = result_data.get("selectors", [])

        for selector in selectors:
            selector_type: int = int(selector.get("selectortype", 0))
            value: str = str(selector.get("selectorvalue", ""))
            date: str = str(selector.get("selectortypevalue", ""))

            if not value:
                continue

            results.append({
                "type": _TYPE_NAMES.get(selector_type, "unknown"),
                "type_code": selector_type,
                "value": value,
                "date": date,
                "bucket": str(selector.get("selectorsystem", "")),
            })

    except httpx.TimeoutException as exc:
        logger.warning("[intelx] Таймаут запроса к IntelX: %s", exc)
    except httpx.ConnectError as exc:
        logger.warning("[intelx] Ошибка подключения к IntelX: %s", exc)
    except Exception as exc:
        logger.warning("[intelx] Неожиданная ошибка phonebook-поиска: %s", exc)

    logger.info("[intelx] Phonebook domain=%s found=%d результатов", domain, len(results))
    return results


def _search_intelligent(
    domain: str,
    api_key: str,
) -> list[dict[str, Any]]:
    """
    Полный поиск через /intelligent/search (требует API-ключ).

    Возвращает богатые результаты с файлами, пастами, форумными постами.
    Используется только если api_key предоставлен.

    Возвращает:
        list[dict] — каждый элемент: {type, value, date, bucket, systemid}
    """
    results: list[dict[str, Any]] = []

    try:
        # Шаг 1: инициируем intelligent search
        search_payload = {
            "term": domain,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": _PUBLIC_API_MAX_RESULTS,
            "timeout": 0,
            "datefrom": "",
            "dateto": "",
            "sort": 4,      # сортировка по дате (новые сначала)
            "media": 0,
            "terminate": [],
        }

        response = httpx.post(
            f"{_INTELX_API_BASE}/intelligent/search",
            json=search_payload,
            headers=_make_headers(api_key),
            timeout=_HTTP_TIMEOUT,
        )

        if response.status_code != 200:
            logger.warning("[intelx] HTTP %d при intelligent search", response.status_code)
            return []

        search_data = response.json()
        task_id: str = search_data.get("id", "")

        if not task_id:
            logger.warning("[intelx] Не получен task_id от /intelligent/search")
            return []

        time.sleep(_REQUEST_DELAY)

        # Шаг 2: получаем результаты
        result_response = httpx.get(
            f"{_INTELX_API_BASE}/intelligent/search/result",
            params={
                "id": task_id,
                "limit": _PUBLIC_API_MAX_RESULTS,
                "offset": 0,
                "previewlines": 3,
            },
            headers=_make_headers(api_key),
            timeout=_HTTP_TIMEOUT,
        )

        if result_response.status_code != 200:
            logger.warning("[intelx] HTTP %d при получении intelligent результатов", result_response.status_code)
            return []

        result_data = result_response.json()
        records: list[dict[str, Any]] = result_data.get("records", [])

        for record in records:
            media_type: int = int(record.get("media", 0))
            name: str = str(record.get("name", ""))
            date: str = str(record.get("date", ""))
            bucket: str = str(record.get("bucket", ""))
            system_id: str = str(record.get("systemid", ""))

            results.append({
                "type": _TYPE_NAMES.get(media_type, "file"),
                "type_code": media_type,
                "value": name,
                "date": date,
                "bucket": bucket,
                "systemid": system_id,
            })

    except httpx.TimeoutException as exc:
        logger.warning("[intelx] Таймаут intelligent search: %s", exc)
    except Exception as exc:
        logger.warning("[intelx] Ошибка intelligent search: %s", exc)

    logger.info("[intelx] Intelligent domain=%s found=%d результатов", domain, len(results))
    return results


def _is_relevant_for_domain(item: dict[str, Any], domain: str) -> bool:
    """
    Фильтрует результаты — оставляем только релевантные для целевого домена.

    Релевантен если:
      - value содержит целевой домен или его TLD-часть
      - type является интересным (email, domain, url)
    """
    value_lower = item.get("value", "").lower()
    domain_lower = domain.lower()

    # Извлекаем корень домена (без субдоменов)
    domain_parts = domain_lower.split(".")
    domain_root = domain_parts[0] if len(domain_parts) >= 1 else domain_lower

    return (
        domain_lower in value_lower
        or domain_root in value_lower
        or item.get("type_code", -1) in _RELEVANT_TYPES
    )


def search_intelx(
    domain: str,
    core_api_url: str,
    internal_secret: str,
    api_key: Optional[str] = None,
) -> dict[str, Any]:
    """
    Поиск упоминаний домена в базе IntelX.io.

    Без api_key использует публичный phonebook-режим (лимит 5 результатов).
    С api_key подключает полный intelligent search.

    Отправляет найденные совпадения в Core API как события forum_mention.

    Аргументы:
        domain          — целевой домен для поиска
        core_api_url    — URL Core API для ingest событий
        internal_secret — секрет для авторизации ingest-запросов
        api_key         — IntelX API ключ (опционально)

    Возвращает:
        {
          "found": N,  — кол-во найденных релевантных результатов
          "sent": K,   — успешно отправленных событий
          "mode": str, — "phonebook" или "intelligent"
        }
    """
    domain_clean = domain.strip().lower()
    logger.info("[intelx] Начало поиска domain=%s mode=%s",
                domain_clean, "intelligent" if api_key else "phonebook")

    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    ingest_headers: dict[str, str] = {"Authorization": f"Bearer {internal_secret}"}

    # Выбираем режим поиска
    if api_key:
        raw_results = _search_intelligent(domain_clean, api_key)
        mode = "intelligent"
    else:
        raw_results = _search_phonebook(domain_clean)
        mode = "phonebook"

    # Фильтруем нерелевантные результаты
    relevant = [item for item in raw_results if _is_relevant_for_domain(item, domain_clean)]

    logger.info(
        "[intelx] domain=%s raw=%d relevant=%d mode=%s",
        domain_clean,
        len(raw_results),
        len(relevant),
        mode,
    )

    found = len(relevant)
    sent = 0

    for item in relevant:
        event: dict[str, Any] = {
            "event_type": "forum_mention",
            "severity": "high",
            "source_type": "darknet_monitor",
            "source_name": "IntelX",
            "target_domain": domain_clean,
            "payload": {
                "match": item.get("value", ""),
                "type": item.get("type", "unknown"),
                "bucket": item.get("bucket", ""),
                "date": item.get("date", ""),
                "mode": mode,
            },
        }

        if _send_ingest_event(ingest_url, ingest_headers, event):
            sent += 1

    logger.info("[intelx] Итого domain=%s found=%d sent=%d", domain_clean, found, sent)

    return {
        "found": found,
        "sent": sent,
        "mode": mode,
    }


def _send_ingest_event(
    ingest_url: str,
    headers: dict[str, str],
    event: dict[str, Any],
) -> bool:
    """
    Отправляет событие в Core API.
    Возвращает True при успешной доставке (accepted или duplicate).
    Изолирована от исключений.
    """
    try:
        response = httpx.post(
            ingest_url,
            json=event,
            headers=headers,
            timeout=_HTTP_TIMEOUT,
        )
        status_val: str = response.json().get("status", "error")
        return status_val in ("accepted", "duplicate")
    except Exception as exc:
        logger.error("[intelx] Ошибка отправки события в Core API: %s", exc)
        return False
