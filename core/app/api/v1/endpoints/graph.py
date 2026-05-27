"""
Attack Path Engine — API для работы с Neo4j-графом зависимостей (задача 9.E).

Все эндпоинты работают в режиме graceful degradation:
если Neo4j недоступен — возвращают SQLite-fallback вместо пустого результата.
"""

import logging

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.models.event import Event
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


async def _find_attack_paths_sqlite(domain: str, db: DBDep) -> list[dict]:
    """
    SQLite-fallback для путей атаки когда Neo4j недоступен.
    Ищет комбинации (открытый сервис + утечка учётных данных) в таблице events.
    """
    _SVC_TYPES = ("exposed_service", "open_port", "vulnerability")
    _CRED_TYPES = ("stealer_log", "credential_leak", "secret_leak")

    svc_res = await db.execute(
        select(Event)
        .where(Event.target_domain == domain, Event.event_type.in_(_SVC_TYPES))
        .order_by(Event.detected_at.desc())
        .limit(10)
    )
    svc_events = list(svc_res.scalars().all())

    cred_res = await db.execute(
        select(Event)
        .where(Event.target_domain == domain, Event.event_type.in_(_CRED_TYPES))
        .order_by(Event.detected_at.desc())
        .limit(10)
    )
    cred_events = list(cred_res.scalars().all())

    if not svc_events or not cred_events:
        return []

    paths: list[dict] = []
    seen: set = set()
    for svc in svc_events[:5]:
        for cred in cred_events[:3]:
            p = svc.payload or {}
            c = cred.payload or {}
            leaked = c.get("email") or c.get("login") or "—"
            key = (svc.target_domain, p.get("port"), leaked)
            if key in seen:
                continue
            seen.add(key)

            if svc.event_type in ("exposed_service", "open_port"):
                paths.append({
                    "asset": svc.target_domain,
                    "port": p.get("port"),
                    "service": p.get("service", "unknown"),
                    "leaked_email": leaked,
                    "attack_type": "direct_access",
                    "risk": "Открытый порт + утечка учётных данных",
                    "risk_score": 100,
                })
            else:
                sev = (svc.severity or "high").lower()
                paths.append({
                    "asset": svc.target_domain,
                    "vuln": p.get("vulnerability_id") or p.get("template_id") or "CVE-unknown",
                    "severity": sev,
                    "leaked_email": leaked,
                    "attack_type": "vuln_plus_cred",
                    "risk": f"Уязвимость {sev.upper()} + утечка учётных данных",
                    "risk_score": 95 if sev == "critical" else 80,
                })

    return paths[:10]


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
    Возвращает найденные пути атаки для домена.

    Путь атаки формируется когда для одного домена одновременно обнаружены:
    - открытый порт/сервис (из событий exposed_service)
    - утечка учётных данных (из событий credential_leak / stealer_log)

    Приоритет: Neo4j → SQLite-fallback.
    """
    await _verify_domain_ownership(domain, db, current_user)
    logger.info("[graph] attack-paths: domain=%s user=%s", domain, current_user.email)
    paths = await find_attack_paths(domain)
    if not paths:
        logger.info("[graph] Neo4j пуст — используем SQLite fallback для %s", domain)
        paths = await _find_attack_paths_sqlite(domain, db)
    return paths


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
