"""
STIX 2.1 export — конвертация AssetEvent в STIX Bundle.
Без stix2 library — ручная генерация JSON (меньше зависимостей).

Маппинг event_type → STIX объекты:
- stealer_log, breach        → indicator (malicious-activity)
- port_scan                  → observed-data (network-traffic)
- nuclei_finding             → vulnerability (CVE или software)
- dark_web_mention,
  ransomware_mention         → threat-actor (tentative)
- остальные                  → observed-data (generic)
"""
import uuid
import json
from datetime import datetime, timezone
from typing import Any


STIX_SPEC_VERSION = "2.1"

# Типы событий, которые дают Indicator при critical/high
_INDICATOR_TYPES = {"stealer_log", "breach"}

# Типы событий для threat-actor
_THREAT_ACTOR_TYPES = {"dark_web_mention", "ransomware_mention"}

# Типы событий для vulnerability
_VULNERABILITY_TYPES = {"nuclei_finding"}


def _stix_id(obj_type: str) -> str:
    """Генерирует STIX-совместимый идентификатор вида type--uuid4."""
    return f"{obj_type}--{uuid.uuid4()}"


def _now() -> str:
    """Возвращает текущее время UTC в формате ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value: Any) -> str:
    """
    Конвертирует created_at/detected_at из события в ISO 8601 UTC строку.
    Принимает datetime-объект или строку.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    if isinstance(value, str):
        # Попытка распарсить строку ISO 8601
        try:
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            pass
    return _now()


def _get_event_ts(event: dict) -> str:
    """Извлекает временную метку из события (detected_at или created_at)."""
    ts = event.get("detected_at") or event.get("created_at")
    if ts is None:
        return _now()
    return _parse_ts(ts)


def event_to_indicator(event: dict) -> dict:
    """
    Конвертирует AssetEvent dict → STIX Indicator object.

    Применяется для событий типа stealer_log и breach с severity critical/high.
    """
    ts = _get_event_ts(event)
    event_type = event.get("event_type", "unknown")
    target_domain = event.get("target_domain", "")
    source_name = event.get("source_name", "")
    payload = event.get("payload") or {}

    # Строим паттерн индикатора: домен как основной маркер угрозы
    if target_domain:
        pattern = f"[domain-name:value = '{target_domain}']"
    else:
        pattern = "[domain-name:value = 'unknown']"

    # Описание: тип события + дополнительный контекст из payload
    desc_parts = [f"Event type: {event_type}"]
    if email := payload.get("email"):
        desc_parts.append(f"email: {email}")
    if login := payload.get("login"):
        desc_parts.append(f"login: {login}")
    if url := payload.get("url"):
        desc_parts.append(f"url: {url}")
    description = "; ".join(desc_parts)

    return {
        "type": "indicator",
        "spec_version": STIX_SPEC_VERSION,
        "id": _stix_id("indicator"),
        "created": ts,
        "modified": ts,
        "name": f"{event_type} on {target_domain}",
        "description": description,
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ts,
        "labels": [event_type, f"severity:{event.get('severity', 'unknown')}"],
        "x_surface_source": source_name,
        "x_surface_event_type": event_type,
    }


def event_to_observed_data(event: dict) -> dict:
    """
    Конвертирует AssetEvent → STIX Observed-Data object.

    Используется для port_scan (network-traffic) и generic событий.
    """
    ts = _get_event_ts(event)
    event_type = event.get("event_type", "unknown")
    target_domain = event.get("target_domain", "")
    source_name = event.get("source_name", "")
    payload = event.get("payload") or {}

    # SCO (STIX Cyber Observable) object внутри observed-data
    if event_type == "port_scan":
        # network-traffic объект для результатов сканирования портов
        port = payload.get("port", 0)
        protocol = payload.get("protocol", "tcp").lower()
        obs_objects = {
            "0": {
                "type": "network-traffic",
                "dst_ref": "1",
                "dst_port": port,
                "protocols": [protocol],
            },
            "1": {
                "type": "domain-name",
                "value": target_domain or "unknown",
            },
        }
    else:
        # Универсальный domain-name объект для прочих событий
        obs_objects = {
            "0": {
                "type": "domain-name",
                "value": target_domain or "unknown",
            }
        }

    return {
        "type": "observed-data",
        "spec_version": STIX_SPEC_VERSION,
        "id": _stix_id("observed-data"),
        "created": ts,
        "modified": ts,
        "first_observed": ts,
        "last_observed": ts,
        "number_observed": 1,
        "object_refs": list(obs_objects.keys()),
        "objects": obs_objects,
        "labels": [event_type, f"severity:{event.get('severity', 'unknown')}"],
        "x_surface_source": source_name,
        "x_surface_event_type": event_type,
        "x_surface_payload_summary": {
            k: str(v) for k, v in payload.items() if k not in ("password", "password_enc")
        },
    }


def event_to_vulnerability(event: dict) -> dict | None:
    """
    Для nuclei_finding событий → STIX Vulnerability object.

    Если в payload есть CVE — используем его как external reference.
    Иначе создаём generic vulnerability по software/target.
    Возвращает None если event_type не nuclei_finding.
    """
    if event.get("event_type") != "nuclei_finding":
        return None

    ts = _get_event_ts(event)
    target_domain = event.get("target_domain", "")
    source_name = event.get("source_name", "")
    payload = event.get("payload") or {}

    # Ищем CVE в payload
    cve_id = payload.get("cve") or payload.get("cve_id") or payload.get("CVE")
    template_id = payload.get("template_id") or payload.get("template") or "unknown"
    severity_label = event.get("severity", "unknown")

    # Имя уязвимости
    if cve_id:
        vuln_name = str(cve_id).upper()
        external_refs = [
            {
                "source_name": "cve",
                "external_id": str(cve_id).upper(),
                "url": f"https://nvd.nist.gov/vuln/detail/{str(cve_id).upper()}",
            }
        ]
    else:
        vuln_name = f"Nuclei: {template_id} on {target_domain}"
        external_refs = [
            {
                "source_name": "nuclei",
                "external_id": template_id,
                "description": f"Nuclei template finding on {target_domain}",
            }
        ]

    return {
        "type": "vulnerability",
        "spec_version": STIX_SPEC_VERSION,
        "id": _stix_id("vulnerability"),
        "created": ts,
        "modified": ts,
        "name": vuln_name,
        "description": (
            f"Nuclei finding on {target_domain}. "
            f"Template: {template_id}. Severity: {severity_label}."
        ),
        "external_references": external_refs,
        "labels": ["nuclei_finding", f"severity:{severity_label}"],
        "x_surface_source": source_name,
        "x_surface_target_domain": target_domain,
    }


def event_to_threat_actor(event: dict) -> dict:
    """
    Для dark_web_mention / ransomware_mention → STIX Threat-Actor (tentative).
    """
    ts = _get_event_ts(event)
    event_type = event.get("event_type", "unknown")
    target_domain = event.get("target_domain", "")
    source_name = event.get("source_name", "")
    payload = event.get("payload") or {}

    # Имя актора: группа из payload или generic
    actor_name = (
        payload.get("group")
        or payload.get("actor")
        or payload.get("threat_actor")
        or f"Unknown actor ({event_type})"
    )

    return {
        "type": "threat-actor",
        "spec_version": STIX_SPEC_VERSION,
        "id": _stix_id("threat-actor"),
        "created": ts,
        "modified": ts,
        "name": str(actor_name),
        "description": (
            f"{event_type} mention related to {target_domain}. "
            f"Source: {source_name}."
        ),
        "threat_actor_types": ["unknown"],
        "sophistication": "unknown",
        "resource_level": "unknown",
        "primary_motivation": "unknown",
        "labels": [event_type, f"severity:{event.get('severity', 'unknown')}"],
        "x_surface_source": source_name,
        "x_surface_target_domain": target_domain,
    }


def _event_to_stix_objects(event: dict) -> list[dict]:
    """
    Конвертирует одно событие в список STIX объектов.
    Возвращает от 1 до 2 объектов (основной + опциональный indicator).
    """
    event_type = event.get("event_type", "unknown")
    severity = event.get("severity", "info")
    objects: list[dict] = []

    if event_type in _VULNERABILITY_TYPES:
        # nuclei_finding → vulnerability
        vuln = event_to_vulnerability(event)
        if vuln:
            objects.append(vuln)
        # Для critical/high добавляем ещё и indicator
        if severity in ("critical", "high"):
            objects.append(event_to_indicator(event))

    elif event_type in _THREAT_ACTOR_TYPES:
        # dark_web_mention / ransomware_mention → threat-actor
        objects.append(event_to_threat_actor(event))
        # Для critical/high добавляем indicator
        if severity in ("critical", "high"):
            objects.append(event_to_indicator(event))

    elif event_type in _INDICATOR_TYPES:
        # stealer_log / breach → indicator всегда
        objects.append(event_to_indicator(event))
        # Дополнительно добавляем observed-data
        objects.append(event_to_observed_data(event))

    else:
        # Все остальные → observed-data
        objects.append(event_to_observed_data(event))
        # Для critical/high → добавляем indicator
        if severity in ("critical", "high"):
            objects.append(event_to_indicator(event))

    return objects


def events_to_stix_bundle(events: list[dict], org_name: str = "SURFACE Platform") -> dict:
    """
    Создаёт STIX 2.1 Bundle из списка событий.

    Включает:
    - Identity object (источник данных)
    - Объекты для каждого события согласно маппингу event_type → STIX

    Args:
        events: Список событий в виде словарей (AssetEvent.as_dict() или аналог)
        org_name: Название организации для Identity object

    Returns:
        STIX Bundle dict, готовый для json.dumps()
    """
    objects: list[dict] = []

    # Identity object — описывает источник данных (платформу)
    identity_ts = _now()
    identity = {
        "type": "identity",
        "spec_version": STIX_SPEC_VERSION,
        "id": _stix_id("identity"),
        "created": identity_ts,
        "modified": identity_ts,
        "name": org_name,
        "identity_class": "system",
        "description": f"SURFACE Attack Surface Monitoring Platform — {org_name}",
    }
    objects.append(identity)

    # Конвертируем каждое событие
    for event in events:
        stix_objs = _event_to_stix_objects(event)
        objects.extend(stix_objs)

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "spec_version": STIX_SPEC_VERSION,
        "objects": objects,
    }
    return bundle


def bundle_to_json(bundle: dict, indent: int = 2) -> str:
    """Сериализует STIX Bundle в JSON-строку."""
    return json.dumps(bundle, ensure_ascii=False, indent=indent, default=str)
