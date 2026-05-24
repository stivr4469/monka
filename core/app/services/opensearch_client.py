"""
OpenSearch client — обёртка с connection pool и retry.

Используется как опциональный Data Lake поверх PostgreSQL:
  - PostgreSQL остаётся source of truth для метаданных и дедупликации
  - OpenSearch индексирует события для полнотекстового поиска

При недоступности OpenSearch — graceful degradation (операции логируются, не падают).
"""
import logging
from typing import Any

from opensearchpy import AsyncOpenSearch, ConnectionError as OSConnectionError
from opensearchpy.exceptions import RequestError

from app.core.config import settings

logger = logging.getLogger(__name__)

# Маппинг индекса easm-events
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
