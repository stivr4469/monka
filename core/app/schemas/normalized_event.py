import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class EventType(str, Enum):
    SUBDOMAIN = "subdomain"
    VULNERABILITY = "vulnerability"
    SECRET_LEAK = "secret_leak"
    EXPOSED_SERVICE = "exposed_service"
    STEALER_LOG = "stealer_log"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceType(str, Enum):
    SUBFINDER = "subfinder"
    NUCLEI = "nuclei"
    GITLEAKS = "gitleaks"
    STEALER_LOG = "stealer_log"
    MANUAL = "manual"


class NormalizedEvent(BaseModel):
    event_type: EventType
    severity: Severity
    source_type: SourceType
    source_name: str = Field(..., min_length=1, max_length=255)
    target_domain: str = Field(..., min_length=1, max_length=255)
    payload: dict[str, Any]
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Вычисляется автоматически для дедупликации
    dedup_hash: str | None = Field(default=None, exclude=True)

    @model_validator(mode="after")
    def compute_dedup_hash(self) -> "NormalizedEvent":
        raw = f"{self.source_type}|{self.target_domain}|{json.dumps(self.payload, sort_keys=True)}"
        self.dedup_hash = hashlib.sha256(raw.encode()).hexdigest()
        return self

    model_config = {"use_enum_values": True}
