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
    EMAIL_BREACH = "email_breach"
    GITHUB_LEAK = "github_leak"
    DARKNET_MENTION = "darknet_mention"
    RANSOMWARE_MENTION = "ransomware_mention"
    FORUM_MENTION = "forum_mention"
    TELEGRAM_LEAK = "telegram_leak"
    PASTE_MENTION = "paste_mention"
    TECH_PROFILE = "tech_profile"
    TLS_FINGERPRINT = "tls_fingerprint"
    DOMAIN_HARDENING = "domain_hardening"
    ACTIVE_SESSION_LEAK = "active_session_leak"
    SESSION_LEAK = "session_leak"
    PASTE_LEAK = "paste_leak"
    HUMAN_INTEL = "human_intel"
    ASSET_DRIFT = "asset_drift"
    PHISHING_DOMAIN = "phishing_domain"
    CREDENTIAL_LEAK = "credential_leak"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    TLS_EXPIRY = "tls_expiry"
    OPEN_S3_BUCKET = "open_s3_bucket"
    GITHUB_SECRET_LEAK = "github_secret_leak"


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
    BREACH_CHECKER = "breach_checker"
    GITHUB_SEARCH = "github_search"
    DARKNET = "darknet"
    RANSOMWATCH = "ransomwatch"
    INTELX = "intelx"
    TELEGRAM = "telegram"
    PASTE = "paste"
    SCANNER = "scanner"
    COOKIE_VALIDATOR = "cookie_validator"
    DARKNET_MONITOR = "darknet_monitor"
    ENRICHMENT = "enrichment"
    OSINT = "osint"
    PASTE_MONITOR = "paste_monitor"
    STEALER_SOURCE = "stealer_source"
    TELEGRAM_MONITOR = "telegram_monitor"
    TELEGRAM_STEALER = "telegram_stealer"
    CRT_SH = "crt.sh"


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

    # 9.H.3: Условие для снятия штрафа Risk Score.
    # Может быть передано явно или проставлено автоматически в ingest.
    condition: str | None = None

    @model_validator(mode="after")
    def compute_dedup_hash(self) -> "NormalizedEvent":
        # Хэш считается от (event_type + target_domain + source_name + json(payload sorted_keys))
        # Это гарантирует дедупликацию одинаковых находок от одного источника на одном домене,
        # но допускает разные события одного типа с разными payload.
        raw = (
            f"{self.event_type}|"
            f"{self.target_domain}|"
            f"{self.source_name}|"
            f"{json.dumps(self.payload, sort_keys=True)}"
        )
        self.dedup_hash = hashlib.sha256(raw.encode()).hexdigest()
        return self

    model_config = {"use_enum_values": True}


class BulkIngestRequest(BaseModel):
    """Схема для батчевой отправки событий — до 1000 штук за один запрос."""

    events: list[NormalizedEvent] = Field(..., max_length=1000)
