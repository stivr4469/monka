"""
CertStream Monitor — реалтайм Certificate Transparency вместо медленного crt.sh.

Два режима работы:
  1. Celery-задача scan_ct_live() — слушает WebSocket certstream.calidog.io N секунд,
     при недоступности — fallback на Google CT logs API (всегда доступен).
  2. Daemon-режим run_daemon() — бесконечный listener для supervisord/systemd.

Зависимость: pip install certstream
Fallback: Google CT logs API — бесплатный, без ключей, всегда работает.
"""
from __future__ import annotations

import base64
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from workers.celery_app import app
from workers.config import settings
from workers.tasks.base import IngestClient

logger = logging.getLogger(__name__)

_LISTEN_WINDOW_SEC = 60       # сколько секунд слушаем в Celery-задаче
_INGEST_BATCH_SIZE = 50       # отправляем событиями батчами

# Google CT Log — Argon (один из крупнейших публичных логов)
_CT_LOG_URL  = "https://ct.googleapis.com/logs/us1/argon2024"
_CT_TIMEOUT  = httpx.Timeout(15.0)


def _check_certstream() -> bool:
    """Проверяет доступность пакета certstream."""
    try:
        import certstream  # noqa: F401
        return True
    except ImportError:
        logger.warning("[certstream] Пакет не установлен: pip install certstream")
        return False


def _make_subdomain_event(subdomain: str, target_domain: str) -> dict[str, Any]:
    return {
        "event_type":   "subdomain_discovered",
        "severity":     "info",
        "source_type":  "scanner",
        "source_name":  "certstream_live",
        "target_domain": target_domain,
        "payload": {
            "subdomain": subdomain,
            "source":    "certificate_transparency",
            "detected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
    }


def _listen_window(
    monitored_domains: list[str],
    window_sec: int,
) -> list[dict[str, Any]]:
    """
    Подключается к CertStream WebSocket и собирает события в течение window_sec секунд.
    Возвращает список ingest-событий для найденных поддоменов.
    """
    import certstream  # noqa: PLC0415 (импорт внутри функции — certstream необязателен)

    collected: list[dict[str, Any]] = []
    stop_event = threading.Event()

    def callback(message: dict, context: Any) -> None:
        if stop_event.is_set():
            return
        if message.get("message_type") != "certificate_update":
            return
        leaf = message.get("data", {}).get("leaf_cert", {})
        all_domains: list[str] = leaf.get("all_domains", [])
        for cert_domain in all_domains:
            cert_domain = cert_domain.lstrip("*.").lower()
            for target in monitored_domains:
                if cert_domain.endswith(f".{target}") or cert_domain == target:
                    logger.debug("[certstream] Новый субдомен: %s → %s", cert_domain, target)
                    collected.append(_make_subdomain_event(cert_domain, target))

    # Запускаем listener в отдельном потоке
    listener_thread = threading.Thread(
        target=certstream.listen_for_events,
        args=(callback,),
        kwargs={"url": "wss://certstream.calidog.io"},
        daemon=True,
    )
    listener_thread.start()

    time.sleep(window_sec)
    stop_event.set()

    logger.info("[certstream] Окно %ds: собрано %d событий", window_sec, len(collected))
    return collected


# ─── Google CT logs API fallback ──────────────────────────────────────────────

def _ct_get_tree_size() -> int:
    """Возвращает текущий размер дерева CT-лога (количество сертификатов)."""
    resp = httpx.get(f"{_CT_LOG_URL}/ct/v1/get-sth", timeout=_CT_TIMEOUT)
    resp.raise_for_status()
    return resp.json()["tree_size"]


def _parse_cert_domains(leaf_bytes: bytes) -> list[str]:
    """
    Разбирает MerkleTreeLeaf (RFC 6962) и возвращает все домены из сертификата.
    Структура leaf_input:
      1b version + 1b leaf_type + 8b timestamp + 2b entry_type + 3b cert_len + DER
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
    except ImportError:
        return []

    # Пропускаем header MerkleTreeLeaf (15 байт) и читаем длину сертификата
    if len(leaf_bytes) < 15:
        return []
    entry_type = int.from_bytes(leaf_bytes[10:12], "big")
    cert_len = int.from_bytes(leaf_bytes[12:15], "big")
    cert_der = leaf_bytes[15:15 + cert_len]
    if not cert_der:
        return []

    try:
        if entry_type == 1:
            # PreCert: leaf содержит TBSCertificate (не полный сертификат)
            # Просто ищем домены в raw-байтах через regex
            import re
            text = cert_der.decode("latin-1", errors="replace")
            return list({
                m.lower().lstrip("*.")
                for m in re.findall(r'[\x20-\x7e]{4,253}\.[\x20-\x7e]{2,6}', text)
                if "." in m and all(c.isascii() for c in m)
            })
        # entry_type == 0: полный DER сертификат
        cert = x509.load_der_x509_certificate(cert_der)
        domains: set[str] = set()
        # CN из Subject
        for attr in cert.subject:
            from cryptography.x509.oid import NameOID
            if attr.oid == NameOID.COMMON_NAME:
                domains.add(attr.value.lower().lstrip("*."))
        # SANs
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for dns_name in san.value.get_values_for_type(x509.DNSName):
                domains.add(dns_name.lower().lstrip("*."))
        except x509.ExtensionNotFound:
            pass
        return list(domains)
    except Exception:
        return []


def _ct_get_entries(start: int, end: int) -> list[list[str]]:
    """Скачивает блок записей CT-лога, возвращает список доменов для каждой записи."""
    resp = httpx.get(
        f"{_CT_LOG_URL}/ct/v1/get-entries",
        params={"start": start, "end": min(end, start + 63)},  # CT API лимит ~64
        timeout=_CT_TIMEOUT,
    )
    resp.raise_for_status()
    raw_entries = resp.json().get("entries", [])

    results = []
    for entry in raw_entries:
        try:
            leaf_b64 = entry.get("leaf_input", "")
            if not leaf_b64:
                continue
            leaf_bytes = base64.b64decode(leaf_b64 + "==")
            domains = _parse_cert_domains(leaf_bytes)
            if domains:
                results.append(domains)
        except Exception:
            pass
    return results


def _extract_domains_from_raw(raw: str, target_domain: str) -> list[str]:
    """Ищет совпадения с target_domain в raw-байтах сертификата (legacy fallback)."""
    import re
    found = re.findall(
        r'(?:[a-zA-Z0-9*](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(target_domain),
        raw,
    )
    return list({d.lower().lstrip("*.") for d in found})


def _scan_ct_certspotter(domain: str) -> list[dict[str, Any]]:
    """
    Fallback: запрашивает Certspotter API (SSLMate) — 100 запросов/час без ключа.
    Индексированный поиск по CT-логам, возвращает все dns_names для domain.
    """
    try:
        resp = httpx.get(
            "https://api.certspotter.com/v1/issuances",
            params={
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            },
            timeout=httpx.Timeout(20.0),
        )
        resp.raise_for_status()
        records = resp.json()
    except Exception as exc:
        logger.error("[ct-certspotter] Ошибка запроса: %s", exc)
        return []

    seen: set[str] = set()
    events = []
    for rec in records:
        for dns_name in rec.get("dns_names", []):
            cert_domain = dns_name.lstrip("*.").lower()
            if (cert_domain.endswith(f".{domain}") or cert_domain == domain) and cert_domain not in seen:
                seen.add(cert_domain)
                events.append(_make_subdomain_event(cert_domain, domain))

    logger.info("[ct-certspotter] domain=%s: %d субдоменов найдено в %d записях",
                domain, len(events), len(records))
    return events


def _scan_ct_google(domain: str, window_sec: int = 30) -> list[dict[str, Any]]:
    """
    Fallback: сначала пробуем crt.sh (индексированный поиск по домену),
    затем как резерв — Google CT raw scan последних 64 записей.
    """
    # Приоритет 1: Certspotter (быстро, точно, indexed)
    events = _scan_ct_certspotter(domain)
    if events:
        return events

    # Приоритет 2: Google CT raw (последние 64 записи) — последний резерв
    logger.warning("[ct-google] crt.sh не дал результатов, пробуем raw CT scan")
    try:
        tree_size = _ct_get_tree_size()
    except Exception as exc:
        logger.error("[ct-google] Не удалось получить tree size: %s", exc)
        return []

    start = max(0, tree_size - 64)
    try:
        all_domain_lists = _ct_get_entries(start, tree_size - 1)
    except Exception as exc:
        logger.error("[ct-google] Ошибка get-entries: %s", exc)
        return []

    seen: set[str] = set()
    raw_events = []
    for domains in all_domain_lists:
        for cert_domain in domains:
            if (cert_domain.endswith(f".{domain}") or cert_domain == domain) and cert_domain not in seen:
                seen.add(cert_domain)
                raw_events.append(_make_subdomain_event(cert_domain, domain))

    logger.info("[ct-google] raw scan: %d совпадений в %d сертах",
                len(raw_events), len(all_domain_lists))
    return raw_events


@app.task(bind=True, name="certstream_monitor.scan_ct_live", max_retries=1)
def scan_ct_live(self, domain: str) -> dict[str, Any]:
    """
    Celery-задача: слушает CertStream N секунд и отправляет новые поддомены в ingest.
    При недоступности certstream.calidog.io — автоматически fallback на Google CT API.
    """
    if not _check_certstream():
        return {"status": "skipped", "reason": "certstream not installed", "new_subdomains": 0}

    logger.info("[certstream] Старт для домена %s, окно %ds", domain, _LISTEN_WINDOW_SEC)
    monitored = [domain]

    try:
        events = _listen_window(monitored, _LISTEN_WINDOW_SEC)
    except Exception as exc:
        logger.error("[certstream] Ошибка WebSocket: %s", exc)
        return {"status": "error", "error": str(exc), "new_subdomains": 0}

    source = "certstream_live"
    if not events:
        logger.warning("[certstream] WebSocket вернул 0 событий — fallback на Google CT API")
        events = _scan_ct_google(domain, _LISTEN_WINDOW_SEC)
        source = "google_ct_fallback"

    if not events:
        return {"status": "ok", "source": source, "new_subdomains": 0}

    # Дедупликация по субдомену
    seen: set[str] = set()
    unique_events: list[dict] = []
    for ev in events:
        sub = ev["payload"]["subdomain"]
        if sub not in seen:
            seen.add(sub)
            unique_events.append(ev)

    # Отправка в ingest батчами
    client = IngestClient(
        core_api_url=settings.CORE_API_URL,
        internal_secret=settings.INTERNAL_API_SECRET,
    )
    sent = 0
    for ev in unique_events:
        try:
            client.send(ev)
            sent += 1
        except Exception as exc:
            logger.warning("[certstream] Ошибка отправки события: %s", exc)

    logger.info("[certstream] %s: %d новых поддоменов отправлено (source=%s)", domain, sent, source)
    return {"status": "ok", "source": source, "new_subdomains": sent}


# ─── Daemon-режим (не Celery) ─────────────────────────────────────────────────

def run_daemon(monitored_domains: list[str]) -> None:
    """
    Бесконечный listener для запуска как отдельный процесс.

    Использование:
        python -c "from workers.tasks.certstream_monitor import run_daemon; run_daemon(['company.com'])"
    """
    if not _check_certstream():
        raise RuntimeError("Пакет certstream не установлен: pip install certstream")

    import certstream  # noqa: PLC0415

    client = IngestClient(
        core_api_url=settings.CORE_API_URL,
        internal_secret=settings.INTERNAL_API_SECRET,
    )

    def callback(message: dict, context: Any) -> None:
        if message.get("message_type") != "certificate_update":
            return
        leaf = message.get("data", {}).get("leaf_cert", {})
        for cert_domain in leaf.get("all_domains", []):
            cert_domain = cert_domain.lstrip("*.").lower()
            for target in monitored_domains:
                if cert_domain.endswith(f".{target}") or cert_domain == target:
                    logger.info("[certstream:daemon] Новый субдомен: %s", cert_domain)
                    try:
                        client.send(_make_subdomain_event(cert_domain, target))
                    except Exception as exc:
                        logger.warning("[certstream:daemon] Ingest error: %s", exc)

    logger.info("[certstream:daemon] Старт listener для %d доменов", len(monitored_domains))
    certstream.listen_for_events(callback, url="wss://certstream.calidog.io")
