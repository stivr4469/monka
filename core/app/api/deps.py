import hashlib
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import decode_access_token
from app.db import get_db
from app.models.user import User
from app.schemas.user import TokenPayload

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")
bearer_scheme = HTTPBearer()

DBDep = Annotated[AsyncSession, Depends(get_db)]


async def get_current_user(
    db: DBDep,
    token: Annotated[str, Depends(oauth2_scheme)],
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Недействительные учётные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        token_data = TokenPayload(**payload)
    except (JWTError, ValueError):
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == token_data.sub))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


async def get_current_user_or_api_key(
    authorization: str = Header(default=""),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    10.F: Поддерживает аутентификацию через JWT и API-ключи (Bearer easm_...).

    Если заголовок начинается с "Bearer easm_" — ищем по SHA-256 хешу ключа.
    Иначе — стандартная JWT-аутентификация.
    """
    if authorization.startswith("Bearer easm_"):
        # Импортируем здесь чтобы избежать циклических импортов
        from app.models.api_key import ApiKey

        raw_key = authorization.removeprefix("Bearer ")
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        result = await db.execute(
            select(ApiKey).where(
                ApiKey.key_hash == key_hash,
                ApiKey.is_active.is_(True),
            )
        )
        api_key = result.scalar_one_or_none()

        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Недействительный API ключ",
            )

        # Проверяем срок действия если задан
        if api_key.expires_at is not None and api_key.expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API ключ истёк",
            )

        # Обновляем last_used_at для аналитики
        api_key.last_used_at = datetime.now(timezone.utc)
        await db.commit()

        # Загружаем пользователя владельца ключа
        user = await db.get(User, api_key.user_id)
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Пользователь ключа не активен",
            )
        return user

    # Fallback: стандартный JWT через OAuth2PasswordBearer
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Недействительные учётные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not authorization.startswith("Bearer "):
        raise credentials_exception

    token = authorization.removeprefix("Bearer ")
    try:
        payload = decode_access_token(token)
        token_data = TokenPayload(**payload)
    except (JWTError, ValueError):
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == token_data.sub))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


def verify_internal_secret(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> None:
    """Проверяет shared secret воркеров."""
    if credentials.credentials != settings.INTERNAL_API_SECRET:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Неверный внутренний ключ")
