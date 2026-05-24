"""
Центр уведомлений — SSE поток + REST (задача 10.I).

Эндпоинты:
  GET  /notifications          — последние 50 уведомлений (непрочитанные первыми)
  POST /notifications/{id}/read — пометить прочитанным
  POST /notifications/read-all  — отметить все прочитанными
  GET  /notifications/count     — {"unread": N} для badge
  GET  /notifications/stream    — SSE поток (EventSource)
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select, update

from app.api.deps import CurrentUser, DBDep
from app.models.notification import Notification

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["notifications"])


# ─── REST эндпоинты ──────────────────────────────────────────────────────────

@router.get(
    "",
    summary="Список уведомлений организации",
)
async def list_notifications(
    db: DBDep,
    current_user: CurrentUser,
) -> list[dict]:
    """
    Возвращает последние 50 уведомлений организации.
    Непрочитанные идут первыми, затем по убыванию времени создания.
    """
    if current_user.organization_id is None:
        return []

    result = await db.execute(
        select(Notification)
        .where(Notification.org_id == current_user.organization_id)
        .order_by(
            Notification.is_read.asc(),      # непрочитанные первыми (False < True)
            Notification.created_at.desc(),  # новейшие сверху внутри каждой группы
        )
        .limit(50)
    )
    notifs = result.scalars().all()

    return [
        {
            "id": n.id,
            "message": n.message,
            "severity": n.severity,
            "is_read": n.is_read,
            "event_id": n.event_id,
            "created_at": n.created_at.isoformat() if n.created_at else None,
        }
        for n in notifs
    ]


@router.get(
    "/count",
    summary="Количество непрочитанных уведомлений",
)
async def count_unread(
    db: DBDep,
    current_user: CurrentUser,
) -> dict:
    """Возвращает {"unread": N} для отображения badge на колокольчике."""
    if current_user.organization_id is None:
        return {"unread": 0}

    from sqlalchemy import func
    result = await db.execute(
        select(func.count(Notification.id)).where(
            Notification.org_id == current_user.organization_id,
            Notification.is_read.is_(False),
        )
    )
    count = result.scalar() or 0
    return {"unread": count}


@router.post(
    "/{notif_id}/read",
    summary="Пометить уведомление прочитанным",
)
async def mark_read(
    notif_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> dict:
    """Помечает одно уведомление как прочитанное."""
    if current_user.organization_id is None:
        return {"status": "ok"}

    await db.execute(
        update(Notification)
        .where(
            Notification.id == notif_id,
            Notification.org_id == current_user.organization_id,
        )
        .values(is_read=True)
    )
    await db.commit()
    return {"status": "ok", "id": notif_id}


@router.post(
    "/read-all",
    summary="Отметить все уведомления прочитанными",
)
async def mark_all_read(
    db: DBDep,
    current_user: CurrentUser,
) -> dict:
    """Отмечает все непрочитанные уведомления организации как прочитанные."""
    if current_user.organization_id is None:
        return {"status": "ok", "updated": 0}

    result = await db.execute(
        update(Notification)
        .where(
            Notification.org_id == current_user.organization_id,
            Notification.is_read.is_(False),
        )
        .values(is_read=True)
    )
    await db.commit()
    return {"status": "ok", "updated": result.rowcount}


# ─── SSE поток ───────────────────────────────────────────────────────────────

@router.get(
    "/stream",
    summary="SSE поток уведомлений (EventSource)",
    response_class=StreamingResponse,
)
async def notifications_stream(
    request: Request,
    current_user: CurrentUser,
    db: DBDep,
) -> StreamingResponse:
    """
    Server-Sent Events поток новых уведомлений.

    Клиент подключается через EventSource('/api/v1/notifications/stream').
    Сервер опрашивает БД каждые 5 секунд и отправляет новые непрочитанные уведомления.
    При разрыве соединения — graceful shutdown через is_disconnected().
    """
    org_id = current_user.organization_id

    async def event_generator():
        # ID последнего отправленного уведомления для фильтрации повторов
        sent_ids: set[str] = set()

        while True:
            # Graceful disconnect — проверяем разрыв клиента
            if await request.is_disconnected():
                logger.debug("[notifications/sse] Клиент отключился org=%s", org_id)
                break

            if org_id is not None:
                try:
                    result = await db.execute(
                        select(Notification)
                        .where(
                            Notification.org_id == org_id,
                            Notification.is_read.is_(False),
                        )
                        .order_by(Notification.created_at.desc())
                        .limit(10)
                    )
                    notifs = result.scalars().all()

                    # Отправляем только новые уведомления (которых ещё не отправляли)
                    new_notifs = [n for n in notifs if n.id not in sent_ids]
                    if new_notifs:
                        data = json.dumps([
                            {
                                "id": n.id,
                                "message": n.message,
                                "severity": n.severity,
                                "event_id": n.event_id,
                                "created_at": n.created_at.isoformat() if n.created_at else None,
                            }
                            for n in new_notifs
                        ])
                        sent_ids.update(n.id for n in new_notifs)
                        yield f"data: {data}\n\n"
                    else:
                        # Heartbeat каждые 5 секунд — держим соединение живым
                        yield ": heartbeat\n\n"

                except Exception as exc:
                    logger.warning("[notifications/sse] Ошибка запроса: %s", exc)
                    yield ": error\n\n"
            else:
                # Пользователь без организации — шлём heartbeat
                yield ": heartbeat\n\n"

            await asyncio.sleep(5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",        # отключает буферизацию в nginx
            "Connection": "keep-alive",
        },
    )
