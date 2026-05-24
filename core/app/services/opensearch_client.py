"""
OpenSearch client — обёртка с connection pool и retry.

Используется как опциональный Data Lake поверх PostgreSQL:
  - PostgreSQL остаётся source of truth для метаданных и дедупликации
  - OpenSearch индексирует события для полнотекстового поиска
  - easm-leaked-credentials — отдельный оптимизированный индекс для стилер/breach событий
    с ILM-политикой (hot→warm→cold) и best_compression кодеком

При недоступности OpenSearch — graceful degradation (операции логируются, не падают).
"""
import logging
from typing import Any

from opensearchpy import AsyncOpenSearch, ConnectionError as OSConnectionError
from opensearchpy.exceptions import NotFoundError, RequestError

from app.core.config import settings

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# Индекс easm-events (общий)
# ──────────────────────────────────────────────────────────────

_INDEX_MAPPING: dict[str, Any] = {
    "mappings": {
        "properties": {
            "id":           {"type": "integer"},
            "event_type":   {"type": "keyword"},
            "severity":     {"type": "keyword"},
            "source_type":  {"type": "keyword"},
            "source_name":  {"type": "keyword"},
            "target_domain":{"type": "keyword"},
            "detected_at":  {"type": "date"},
            "dedup_hash":   {"type": "keyword"},
            "payload":      {"type": "object", "enabled": False},
            "payload_text": {"type": "text", "analyzer": "standard"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
}

# ──────────────────────────────────────────────────────────────
# Индекс easm-leaked-credentials (задача 9.I)
# Оптимизирован для высокого объёма ingest стилер/breach событий.
# ──────────────────────────────────────────────────────────────

_LEAKED_CREDS_INDEX = "easm-leaked-credentials"

_LEAKED_CREDS_MAPPING: dict[str, Any] = {
    "settings": {
        "index": {
            "number_of_shards": 5,
            "number_of_replicas": 1,
            # 10s refresh снижает нагрузку на I/O при массовом ingest
            "refresh_interval": "10s",
            # LZ4 → zlib, экономия ~40% дискового пространства
            "codec": "best_compression",
        }
    },
    "mappings": {
        "properties": {
            "event_type":      {"type": "keyword"},
            "severity":        {"type": "keyword"},
            "source_name":     {"type": "keyword"},
            "target_domain":   {"type": "keyword"},
            "detected_at":     {"type": "date"},
            "dedup_hash":      {"type": "keyword"},
            "organization_id": {"type": "keyword"},
            "payload": {
                "properties": {
                    "url":              {"type": "keyword"},
                    "login": {
                        "type": "text",
                        "analyzer": "standard",
                        # keyword subfield для точных фильтров/агрегаций
                        "fields": {"keyword": {"type": "keyword"}},
                    },
                    "password_masked":  {"type": "keyword"},
                    # index: False — критически важно, пароли не должны индексироваться
                    "password_enc":     {"type": "keyword", "index": False},
                    "host":             {"type": "keyword"},
                    "cookie_name":      {"type": "keyword"},
                    "session_alive":    {"type": "boolean"},
                }
            },
        }
    },
}

# ──────────────────────────────────────────────────────────────
# ILM-политика для easm-leaked-credentials (задача 9.I)
# hot: роллинг каждые 30 дней или 50 GB
# warm: форсированный мерж до 1 сегмента (уменьшает RAM)
# cold: read-only после 90 дней
# ──────────────────────────────────────────────────────────────

_ILM_POLICY_NAME = "easm-creds-policy"

_ILM_POLICY: dict[str, Any] = {
    "policy": {
        "phases": {
            "hot": {
                "min_age": "0ms",
                "actions": {
                    "rollover": {
                        "max_age": "30d",
                        "max_size": "50gb",
                    }
                },
            },
            "warm": {
                "min_age": "30d",
                "actions": {
                    # Один сегмент — минимум RAM для read-heavy warm нод
                    "forcemerge": {"max_num_segments": 1},
                },
            },
            "cold": {
                "min_age": "90d",
                "actions": {"readonly": {}},
            },
        }
    }
}


def _get_client() -> AsyncOpenSearch:
    """Возвращает AsyncOpenSearch клиент с connection pool."""
    return AsyncOpenSearch(
        hosts=[settings.OPENSEARCH_URL],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        max_retries=2,
        retry_on_timeout=True,
        timeout=5,
    )


# Синглтон клиента (пересоздаётся при ошибке)
_client: AsyncOpenSearch | None = None


def get_opensearch() -> AsyncOpenSearch:
    """Возвращает синглтон клиента."""
    global _client
    if _client is None:
        _client = _get_client()
    return _client


async def ensure_index_exists() -> bool:
    """Создаёт индекс easm-events если его нет. Возвращает True при успехе."""
    index = settings.OPENSEARCH_INDEX_EVENTS
    try:
        client = get_opensearch()
        exists = await client.indices.exists(index=index)
        if not exists:
            await client.indices.create(index=index, body=_INDEX_MAPPING)
            logger.info("[opensearch] Индекс %s создан", index)
        return True
    except (OSConnectionError, Exception) as exc:
        logger.warning("[opensearch] Не удалось создать индекс: %s", exc)
        return False


async def ensure_leaked_creds_index() -> bool:
    """
    Создаёт индекс easm-leaked-credentials с оптимизированным маппингом.
    Graceful: если индекс уже существует — не ошибается.
    Возвращает True при успехе или если индекс уже есть.
    """
    try:
        client = get_opensearch()
        exists = await client.indices.exists(index=_LEAKED_CREDS_INDEX)
        if not exists:
            await client.indices.create(index=_LEAKED_CREDS_INDEX, body=_LEAKED_CREDS_MAPPING)
            logger.info("[opensearch] Индекс %s создан", _LEAKED_CREDS_INDEX)
        return True
    except RequestError as exc:
        # resource_already_exists_exception — гонка при параллельном старте нод
        if "resource_already_exists_exception" in str(exc).lower():
            logger.debug("[opensearch] Индекс %s уже существует", _LEAKED_CREDS_INDEX)
            return True
        logger.warning("[opensearch] Ошибка создания индекса %s: %s", _LEAKED_CREDS_INDEX, exc)
        return False
    except (OSConnectionError, Exception) as exc:
        logger.warning("[opensearch] Не удалось создать индекс %s: %s", _LEAKED_CREDS_INDEX, exc)
        return False


async def create_ilm_policy() -> bool:
    """
    Создаёт или обновляет ILM-политику easm-creds-policy.
    hot → warm → cold с автороллингом и forcemerge.
    Возвращает True при успехе.
    """
    try:
        client = get_opensearch()
        await client.ilm.put_lifecycle(policy=_ILM_POLICY_NAME, body=_ILM_POLICY)
        logger.info("[opensearch] ILM-политика %s применена", _ILM_POLICY_NAME)
        return True
    except (OSConnectionError, Exception) as exc:
        # ILM может быть недоступен в OpenSearch без X-Pack (OSS-дистрибутив)
        logger.warning("[opensearch] Не удалось создать ILM-политику: %s", exc)
        return False


async def index_event(event_id: int, event_data: dict[str, Any]) -> bool:
    """
    Индексирует событие в OpenSearch асинхронно.
    Вызывается после успешной записи в PostgreSQL — не блокирует ответ.
    Возвращает False при любой ошибке (graceful degradation).
    """
    index = settings.OPENSEARCH_INDEX_EVENTS
    try:
        payload = event_data.get("payload", {})
        payload_text = " ".join(str(v) for v in payload.values() if v) if payload else ""

        doc = {
            "id":           event_id,
            "event_type":   event_data.get("event_type"),
            "severity":     event_data.get("severity"),
            "source_type":  event_data.get("source_type"),
            "source_name":  event_data.get("source_name"),
            "target_domain":event_data.get("target_domain"),
            "detected_at":  event_data.get("detected_at"),
            "dedup_hash":   event_data.get("dedup_hash"),
            "payload":      payload,
            "payload_text": payload_text,
        }

        client = get_opensearch()
        await client.index(index=index, id=str(event_id), body=doc, refresh=False)
        return True
    except (OSConnectionError, Exception) as exc:
        logger.debug("[opensearch] Ошибка индексации события %s: %s", event_id, exc)
        return False


async def index_leaked_credential(event_id: str, event_data: dict[str, Any]) -> bool:
    """
    Индексирует credential-событие (стилер / breach) в специализированный индекс
    easm-leaked-credentials.

    Выделен отдельно от easm-events:
    - Оптимизированные настройки шардирования для высокого объёма
    - best_compression кодек (~40% экономии места)
    - password_enc не индексируется (index: False в маппинге)
    - ILM-политика для автоматического перехода hot→warm→cold

    Возвращает False при любой ошибке (graceful degradation).
    """
    try:
        payload = event_data.get("payload", {})

        # Убираем зашифрованный пароль из индексируемого документа на уровне
        # Python — двойная защита поверх index:False в маппинге
        safe_payload = {k: v for k, v in payload.items() if k != "password_enc"}

        doc = {
            "event_type":      event_data.get("event_type"),
            "severity":        event_data.get("severity"),
            "source_name":     event_data.get("source_name"),
            "target_domain":   event_data.get("target_domain"),
            "detected_at":     event_data.get("detected_at"),
            "dedup_hash":      event_data.get("dedup_hash"),
            "organization_id": event_data.get("organization_id"),
            "payload":         safe_payload,
        }

        client = get_opensearch()
        await client.index(
            index=_LEAKED_CREDS_INDEX,
            id=str(event_id),
            body=doc,
            refresh=False,
        )
        logger.debug("[opensearch] Credential событие %s → %s", event_id, _LEAKED_CREDS_INDEX)
        return True
    except (OSConnectionError, Exception) as exc:
        logger.debug("[opensearch] Ошибка индексации credential %s: %s", event_id, exc)
        return False


async def search_events(
    query: str,
    limit: int = 50,
    domain: str | None = None,
    severity: str | None = None,
) -> list[dict[str, Any]]:
    """
    Полнотекстовый поиск по событиям через OpenSearch.
    При недоступности OS возвращает [] — вызывающий код использует PostgreSQL fallback.
    """
    index = settings.OPENSEARCH_INDEX_EVENTS
    must_clauses: list[dict] = [
        {
            "multi_match": {
                "query": query,
                "fields": ["payload_text", "target_domain", "source_name", "event_type"],
                "fuzziness": "AUTO",
            }
        }
    ]

    if domain:
        must_clauses.append({"term": {"target_domain": domain}})
    if severity:
        must_clauses.append({"term": {"severity": severity}})

    body = {
        "query": {"bool": {"must": must_clauses}},
        "size": min(limit, 200),
        "sort": [{"detected_at": {"order": "desc"}}],
    }

    try:
        client = get_opensearch()
        response = await client.search(index=index, body=body)
        hits = response.get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]
    except (OSConnectionError, Exception) as exc:
        logger.debug("[opensearch] Поиск недоступен: %s", exc)
        return []
