import re

from pydantic import BaseModel, Field, field_validator


class AssetCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)
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

    model_config = {"from_attributes": True}
