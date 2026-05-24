"""
Pydantic схемы для правил алертов.
"""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

# Допустимые уровни серьёзности
SeverityLevel = Literal["info", "low", "medium", "high", "critical"]

# Допустимые типы событий (должны соответствовать NormalizedEvent.EventType)
VALID_EVENT_TYPES = {
    "subdomain", "vulnerability", "secret_leak", "exposed_service",
    "stealer_log", "email_breach", "github_leak",
    "darknet_mention", "ransomware_mention", "forum_mention",
    "telegram_leak", "paste_mention",
}


class AlertRuleCreate(BaseModel):
    """Схема создания нового правила алерта."""

    name: str = Field(..., min_length=1, max_length=255, description="Название правила")
    target_domain: str | None = Field(
        default=None,
        max_length=255,
        description="Домен для фильтрации. None = все домены организации",
    )
    min_severity: SeverityLevel = Field(
        default="medium",
        description="Минимальный уровень серьёзности для срабатывания",
    )
    event_types: list[str] | None = Field(
        default=None,
        description="Список типов событий. None = все типы",
    )
    telegram_chat_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Telegram chat_id (например -1001234567890)",
    )
    is_active: bool = Field(default=True, description="Активно ли правило")

    @field_validator("event_types")
    @classmethod
    def validate_event_types(cls, v: list[str] | None) -> list[str] | None:
        """Проверяет что указаны только допустимые типы событий."""
        if v is None:
            return v
        if not v:
            raise ValueError("event_types не может быть пустым списком — используйте None для всех типов")
        unknown = set(v) - VALID_EVENT_TYPES
        if unknown:
            raise ValueError(f"Неизвестные типы событий: {unknown}. Допустимые: {VALID_EVENT_TYPES}")
        return v

    @field_validator("target_domain")
    @classmethod
    def normalize_domain(cls, v: str | None) -> str | None:
        """Приводит домен к нижнему регистру."""
        if v is not None:
            return v.strip().lower()
        return v

    @field_validator("telegram_chat_id")
    @classmethod
    def validate_chat_id(cls, v: str) -> str:
        """Telegram chat_id — число или строка начинающаяся с @."""
        v = v.strip()
        if not v:
            raise ValueError("telegram_chat_id не может быть пустым")
        # Принимаем числовые ID (включая отрицательные для групп) и @username
        if not (v.lstrip("-").isdigit() or v.startswith("@")):
            raise ValueError("telegram_chat_id должен быть числовым ID или @username")
        return v


class AlertRuleUpdate(BaseModel):
    """Схема частичного обновления правила алерта."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    target_domain: str | None = None
    min_severity: SeverityLevel | None = None
    event_types: list[str] | None = None
    telegram_chat_id: str | None = Field(default=None, min_length=1, max_length=100)
    is_active: bool | None = None

    @field_validator("event_types")
    @classmethod
    def validate_event_types(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        if not v:
            raise ValueError("event_types не может быть пустым списком")
        unknown = set(v) - VALID_EVENT_TYPES
        if unknown:
            raise ValueError(f"Неизвестные типы событий: {unknown}")
        return v


class AlertRuleRead(BaseModel):
    """Схема чтения правила алерта (ответ API)."""

    id: str
    organization_id: str
    name: str
    target_domain: str | None
    min_severity: str
    event_types: list[str] | None
    telegram_chat_id: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}
