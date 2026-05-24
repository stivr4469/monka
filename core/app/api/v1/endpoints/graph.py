"""
Attack Path Engine — API для работы с Neo4j-графом зависимостей (задача 9.E).

Все эндпоинты работают в режиме graceful degradation:
если Neo4j недоступен — возвращают пустой результат вместо 503.
"""

import logging

from fastapi import APIRouter, Query

from app.api.deps import CurrentUser
from app.services.graph_client import find_attack_paths, get_domain_graph

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get(
    "/{domain}/attack-paths",
    summary="Пути атаки для домена",
    response_description="Список обнаруженных путей атаки",
)
async def get_attack_paths(
    domain: str,
    current_user: CurrentUser,
) -> list[dict]:
    """
    Возвращает найденные пути атаки для домена на основе данных Neo4j-графа.

    Путь атаки формируется когда для одного домена одновременно обнаружены:
    - открытый порт/сервис (из событий exposed_service)
    - утечка учётных данных (из событий credential_leak / stealer_log)

    Пустой список означает либо отсутствие данных в графе,
    либо что Neo4j недоступен.
    """
    logger.info(
        "[graph] Запрос attack-paths: domain=%s user=%s",
        domain,
        current_user.email,
    )
    return await find_attack_paths(domain)


@router.get(
    "/{domain}/visualization",
    summary="Граф домена для визуализации",
    response_description="Граф в формате {nodes, edges} для D3.js / Vis.js",
)
async def get_graph_visualization(
    domain: str,
    current_user: CurrentUser,
    limit: int = Query(default=200, ge=1, le=1000, description="Максимум нод"),
) -> dict:
    """
    Возвращает граф домена (все ноды и связи) для клиентской визуализации.

    Формат:
        {
            "nodes": [{"id": "1", "label": "acme.com", "type": "Domain"}, ...],
            "edges": [{"source": "1", "target": "2", "label": "HAS_SUBDOMAIN"}, ...]
        }

    Совместим с D3.js force-directed graph и Vis.js network.
    """
    logger.info(
        "[graph] Запрос visualization: domain=%s user=%s",
        domain,
        current_user.email,
    )
    return await get_domain_graph(domain)
