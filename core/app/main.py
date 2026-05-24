import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import select

from app.api.v1.router import api_router
from app.core.config import get_settings, settings, validate_secrets
from app.core.rate_limit import limiter
from app.core.security import hash_password
from app.db import AsyncSessionLocal, engine
from app.middleware.logging_middleware import LoggingMiddleware
from app.models.api_key import ApiKey  # noqa: F401 — регистрирует таблицу в Base.metadata
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.base import Base
from app.models.notification import Notification  # noqa: F401
from app.models.organization import Organization
from app.models.user import User
from app.services.graph_client import close_driver, ensure_constraints
from app.services.opensearch_client import (
    create_ilm_policy,
    ensure_index_exists,
    ensure_leaked_creds_index,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # CRITICAL-2: проверяем что секреты не оставлены дефолтными
    validate_secrets(get_settings())

    # Создаём таблицы (только для dev; в prod — Alembic)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Создаём суперпользователя при первом запуске
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(User).where(User.email == settings.FIRST_SUPERUSER_EMAIL)
        )
        if result.scalar_one_or_none() is None:
            user = User(
                email=settings.FIRST_SUPERUSER_EMAIL,
                hashed_password=hash_password(settings.FIRST_SUPERUSER_PASSWORD),
                is_superuser=True,
            )
            db.add(user)
            await db.flush()
            # Создаём дефолтную организацию и привязываем суперюзера
            org = Organization(name="Default Org", slug="default")
            db.add(org)
            await db.flush()
            user.organization_id = org.id
            await db.commit()
            logger.info("Суперпользователь создан: %s", settings.FIRST_SUPERUSER_EMAIL)

    # 7.C.1: OpenSearch — создаём общий индекс событий (graceful degradation)
    await ensure_index_exists()

    # 9.I: OpenSearch — специализированный индекс для credential-утечек
    await ensure_leaked_creds_index()

    # 9.I: OpenSearch ILM-политика hot→warm→cold для easm-leaked-credentials
    await create_ilm_policy()

    # 9.E: Neo4j — создаём constraints если сервер доступен (graceful degradation)
    await ensure_constraints()

    yield

    # Graceful shutdown — закрываем Neo4j-соединение
    await close_driver()


app = FastAPI(
    title="EASM Platform — Core API",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Подключаем slowapi: state хранит limiter, обработчик отдаёт 429 Too Many Requests
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware добавляются в обратном порядке (LIFO) — LoggingMiddleware
# должна быть последней добавленной чтобы обернуть все запросы первой
app.add_middleware(
    CORSMiddleware,
    # Читаем из настроек — не хардкодим origins
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# Middleware структурированного логирования
app.add_middleware(LoggingMiddleware)

app.include_router(api_router)


@app.get("/health", tags=["health"])
async def health() -> dict:
    return {"status": "ok"}


# Статический дашборд — монтируем последним чтобы не перехватывать API маршруты
_static_dir = Path(__file__).parent.parent / "static"
if _static_dir.exists():
    app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="static")
