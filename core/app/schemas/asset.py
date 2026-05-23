from pydantic import BaseModel, Field


class AssetCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)
    description: str | None = Field(default=None, max_length=1000)


class AssetUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=1000)
    is_active: bool | None = None


class AssetRead(BaseModel):
    id: str
    domain: str
    description: str | None
    is_active: bool
    organization_id: str

    model_config = {"from_attributes": True}
