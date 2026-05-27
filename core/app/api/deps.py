import hashlib
import hmac
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
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

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Недействительные учётные данные",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    db: DBDep,
    credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer_scheme)],
) -> User:
    """Аутентификация через JWT или API-ключ (Bearer easm_...).

    HTTPBearer гарантирует наличие заголовка Authorization: Bearer <token>
    и выводит иконку замка в Swagger UI.
    """
    token = credentials.credentials

    # Ветка API-ключа: префикс easm_
    if token.startswith("easm_"):
        from app.models.api_key import ApiKey

        key_hash = hashlib.sha256(token.encode()).hexdigest()
        key_result = await db.execute(
            select(ApiKey).where(
                ApiKey.key_hash == key_hash,
                ApiKey.is_active.is_(True),
            )
        )
        api_key = key_result.scalar_one_or_none()
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Недействительный API ключ",
            )
        if api_key.expires_at is not None and api_key.expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API ключ истёк",
            )
        api_key.last_used_at = datetime.now(timezone.utc)
        await db.commit()
        user = await db.get(User, api_key.user_id)
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Пользователь ключа не активен",
            )
        return user

    # Ветка JWT
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

# Обратная совместимость — используется в некоторых местах явно
get_current_user_or_api_key = get_current_user


def verify_internal_secret(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer_scheme)],
) -> None:
    """Проверяет shared secret воркеров."""
    if not hmac.compare_digest(credentials.credentials, settings.INTERNAL_API_SECRET):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Неверный внутренний ключ")
