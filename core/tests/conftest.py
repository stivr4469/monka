import sys
import uuid
from pathlib import Path
from typing import AsyncGenerator

# Добавляем workers в sys.path чтобы тесты парсера видели tasks.*
_workers_path = str(Path(__file__).parents[2] / "workers")
if _workers_path not in sys.path:
    sys.path.insert(0, _workers_path)

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core import rate_limit as _rate_limit_module
from app.core.security import hash_password
from app.db import get_db
from app.main import app
from app.models.base import Base
from app.models.user import User

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestSessionLocal = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)

# Пароль для всех тестовых пользователей
TEST_PASSWORD = "testpassword"


@pytest.fixture(autouse=True)
def use_memory_rate_limiter():
    """Сбрасывает счётчики rate limiter перед каждым тестом.

    Декораторы @limiter.limit() захватывают оригинальный объект Limiter в замыкание,
    поэтому замена limiter целиком не помогает — нужно сбрасывать .storage.reset()
    именно того экземпляра, который был использован при декорировании роутов.
    """
    original_limiter = _rate_limit_module.limiter
    app.state.limiter = original_limiter  # убеждаемся, что app.state указывает на тот же объект
    original_limiter._storage.reset()    # обнуляем счётчики перед каждым тестом
    yield


@pytest_asyncio.fixture(autouse=True, scope="session")
async def setup_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with TestSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def superuser(db_session: AsyncSession) -> User:
    # Уникальный email за каждый тест — избегаем UNIQUE конфликта в in-memory БД
    email = f"super_{uuid.uuid4().hex[:8]}@test.com"
    user = User(
        email=email,
        hashed_password=hash_password(TEST_PASSWORD),
        is_superuser=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def superuser_token(client: AsyncClient, superuser: User) -> str:
    resp = await client.post(
        "/api/v1/auth/token",
        data={"username": superuser.email, "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]
