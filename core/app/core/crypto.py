"""
AES-шифрование паролей из стилер-логов (Fernet = AES-128-CBC + HMAC-SHA256).

Ключ выводится из INTERNAL_API_SECRET через SHA-256 → URL-safe base64.
Таким образом workers и core используют один ключ без отдельной настройки.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken


def _fernet(secret: str) -> Fernet:
    raw = hashlib.sha256(secret.encode()).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)


def encrypt_password(password: str, secret: str) -> str:
    """Шифрует пароль, возвращает URL-safe base64 строку."""
    if not password:
        return ""
    return _fernet(secret).encrypt(password.encode()).decode()


def decrypt_password(token: str, secret: str) -> str:
    """Расшифровывает токен. Raises ValueError при неверном ключе/токене."""
    if not token:
        return ""
    try:
        return _fernet(secret).decrypt(token.encode()).decode()
    except (InvalidToken, Exception) as exc:
        raise ValueError(f"Не удалось расшифровать пароль: {exc}") from exc
