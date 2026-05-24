"""
AES-шифрование паролей — копия core/app/core/crypto.py для воркеров.
Ключ выводится из INTERNAL_API_SECRET (общий для core и workers).
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken


def _fernet(secret: str) -> Fernet:
    raw = hashlib.sha256(secret.encode()).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)


def encrypt_password(password: str, secret: str) -> str:
    if not password:
        return ""
    return _fernet(secret).encrypt(password.encode()).decode()


def decrypt_password(token: str, secret: str) -> str:
    if not token:
        return ""
    try:
        return _fernet(secret).decrypt(token.encode()).decode()
    except (InvalidToken, Exception) as exc:
        raise ValueError(f"Не удалось расшифровать: {exc}") from exc
