"""
Attack Path Engine — API для работы с Neo4j-графом зависимостей (задача 9.E).

Все эндпоинты работают в режиме graceful degradation:
если Neo4j недоступен — возвращают пустой результат вместо 503.
"""

import logging

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.services.graph_client import find_attack_paths, get_domain_graph

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/graph", tags=["graph"])


async def _verify_domain_ownership(domain: str, db: DBDep, current_user: CurrentUser) -> None:
    """HIGH-4 / CRITICAL-6: проверка что домен принадлежит организации текущего пользователя."""
    result = await db.execute(
        select(Asset).where(
            Asset.domain == domain,
            Asset.organization_id == current_user.organization_id,
        )
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Домен не найден")


@router.get(
    "/{domain}/attack-paths",
    summary="Пути атаки для домена",
    response_description="Список обнаруженных путей атаки",
)
async def get_attack_paths(
    domain: str,
    db: DBDep,
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
    await _verify_domain_ownership(domain, db, current_user)
    logger.info("[graph] attack-paths: domain=%s user=%s", domain, current_user.email)
    return await find_attack_paths(domain)


@router.get(
    "/{domain}/visualization",
    summary="Граф домена для визуализации",
    response_description="Граф в формате {nodes, edges} для D3.js / Vis.js",
)
async def get_graph_visualization(
    domain: str,
    db: DBDep,
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
    await _verify_domain_ownership(domain, db, current_user)
    logger.info("[graph] visualization: domain=%s user=%s", domain, current_user.email)
    return await get_domain_graph(domain)
