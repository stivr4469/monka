import pytest
from app.schemas.normalized_event import NormalizedEvent, EventType, SourceType, Severity


def test_all_worker_event_types_valid():
    # Подтверждаем что все значения, реально отправляемые воркерами, приняты схемой
    for et in [
        "exposed_service",
        "subdomain",
        "vulnerability",
        "tech_profile",
        "tls_fingerprint",
        "darknet_mention",
        "phishing_domain",
        "open_s3_bucket",
        "subdomain_takeover",
    ]:
        assert et in [e.value for e in EventType], f"Отсутствует EventType: {et}"


def test_all_worker_source_types_valid():
    for st in [
        "scanner",
        "subfinder",
        "nuclei",
        "darknet_monitor",
        "paste_monitor",
        "cookie_validator",
        "stealer_log",
    ]:
        assert st in [s.value for s in SourceType], f"Отсутствует SourceType: {st}"


def test_normalized_event_validates():
    event = NormalizedEvent(
        event_type="subdomain",
        severity="info",
        source_type="subfinder",
        source_name="subfinder",
        target_domain="example.com",
        payload={"subdomain": "www.example.com"},
    )
    assert event.event_type == EventType.SUBDOMAIN
