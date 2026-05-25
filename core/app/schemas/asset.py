import re

from pydantic import BaseModel, Field, field_validator

from app.models.asset import VALID_ASSET_TYPES


class AssetCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)
    description: str | None = Field(default=None, max_length=1000)
    # 12.C: тип актива при создании (по умолчанию primary)
    asset_type: str = Field(default="primary", max_length=50)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if "://" in v or "/" in v:
            raise ValueError("Домен не должен содержать схему (://) или путь (/)")
        pattern = r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Недопустимый формат домена")
        return v

    @field_validator("asset_type")
    @classmethod
    def validate_asset_type(cls, v: str) -> str:
        if v not in VALID_ASSET_TYPES:
            raise ValueError(f"Недопустимый тип актива: {v}. Допустимые: {VALID_ASSET_TYPES}")
        return v


class AssetUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=1000)
    is_active: bool | None = None
    # Коэффициент важности актива: влияет на формулу risk-score (0.1 = незначимый, 2.0 = критичный)
    importance: float | None = Field(default=None, ge=0.1, le=2.0)


class AssetRead(BaseModel):
    id: str
    domain: str
    description: str | None
    is_active: bool
    organization_id: str
    # Коэффициент важности, возвращается в ответе API
    importance: float = 1.0
    # 12.C: тип актива и ссылка на родителя
    asset_type: str = "primary"
    parent_asset_id: str | None = None

    model_config = {"from_attributes": True}


# 12.C: Схема для создания supply chain (vendor/subsidiary) актива
class SupplyChainCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)
    asset_type: str = Field(default="vendor", max_length=50)
    description: str | None = Field(default=None, max_length=1000)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if "://" in v or "/" in v:
            raise ValueError("Домен не должен содержать схему (://) или путь (/)")
        pattern = r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Недопустимый формат домена")
        return v

    @field_validator("asset_type")
    @classmethod
    def validate_asset_type(cls, v: str) -> str:
        # Supply chain активы не могут быть типа primary
        allowed = {"vendor", "subsidiary"}
        if v not in allowed:
            raise ValueError(f"Тип supply chain актива должен быть одним из: {allowed}")
        return v
