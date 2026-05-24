from pydantic import BaseModel, Field


class AssetCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)
    description: str | None = Field(default=None, max_length=1000)


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
