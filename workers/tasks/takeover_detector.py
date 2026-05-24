"""
Воркер: обнаружение уязвимых поддоменов к захвату (Subdomain Takeover).

Как работает: если поддомен имеет CNAME-запись указывающую на внешний сервис
(GitHub Pages, Heroku, S3, Shopify...) который был удалён или не занят —
злоумышленник может зарегистрировать тот ресурс и получить контроль над поддоменом.
"""
import logging
import ssl
import socket
from datetime import datetime, timezone
from typing import NamedTuple

import dns.resolver
import httpx

from tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

# Таймаут HTTP-запроса при проверке fingerprint (секунды)
_HTTP_TIMEOUT = 10.0

# Максимальный размер тела ответа для fingerprint-поиска (байт)
_MAX_BODY_SIZE = 65_536  # 64 КБ — достаточно для любой error-страницы


# ──────────────────────────────────────────────────────────────────────────────
# База fingerprints уязвимых сервисов
# ──────────────────────────────────────────────────────────────────────────────

_TAKEOVER_FINGERPRINTS: dict[str, dict] = {
    "github.io": {
        "error_body": "There isn't a GitHub Pages site here",
        "severity": "critical",
        "service": "GitHub Pages",
    },
    "amazonaws.com": {
        "error_body": "NoSuchBucket",
        "severity": "critical",
        "service": "AWS S3",
    },
    "herokuapp.com": {
        "error_body": "No such app",
        "severity": "critical",
        "service": "Heroku",
    },
    "azurewebsites.net": {
        "error_body": "404 Web Site not found",
        "severity": "high",
        "service": "Azure Web Apps",
    },
    "cloudfront.net": {
        "error_body": "ERROR: The request could not be satisfied",
        "severity": "high",
        "service": "AWS CloudFront",
    },
    "shopify.com": {
        "error_body": "Sorry, this shop is currently unavailable",
        "severity": "high",
        "service": "Shopify",
    },
    "fastly.net": {
        "error_body": "Fastly error: unknown domain",
        "severity": "high",
        "service": "Fastly CDN",
    },
    "pantheon.io": {
        "error_body": "The gods are wise, but do not know of the site",
        "severity": "medium",
        "service": "Pantheon",
    },
    "ghost.io": {
        "error_body": "The thing you were looking for is no longer here",
        "severity": "medium",
        "service": "Ghost",
    },
    "surge.sh": {
        "error_body": "project not found",
        "severity": "medium",
        "service": "Surge",
    },
    # Дополнительные сервисы для расширенного покрытия
    "netlify.app": {
        "error_body": "Not Found - Request ID",
        "severity": "high",
        "service": "Netlify",
    },
    "vercel.app": {
        "error_body": "The deployment you are trying to access does not exist",
        "severity": "high",
        "service": "Vercel",
    },
    "readthedocs.io": {
        "error_body": "unknown to Read the Docs",
        "severity": "medium",
        "service": "ReadTheDocs",
    },
    "zendesk.com": {
        "error_body": "Help Center Closed",
        "severity": "medium",
        "service": "Zendesk",
    },
    "webflow.io": {
        "error_body": "The page you are looking for doesn't exist or has been moved",
        "severity": "medium",
        "service": "Webflow",
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# DNS резолвинг
# ──────────────────────────────────────────────────────────────────────────────

def _get_cname(subdomain: str) -> str | None:
    """
    Резолвит CNAME-запись для поддомена.

    Возвращает target CNAME как строку (в нижнем регистре без trailing dot),
    или None если CNAME-записи нет или домен не существует.
    """
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        # Берём первый CNAME target, убираем trailing dot
        target = str(answers[0].target).rstrip(".")
        return target.lower()
    except dns.resolver.NXDOMAIN:
        logger.debug("[takeover] NXDOMAIN для %s", subdomain)
        return None
    except dns.resolver.NoAnswer:
        logger.debug("[takeover] Нет CNAME-записи для %s", subdomain)
        return None
    except dns.resolver.NoNameservers:
        logger.debug("[takeover] Нет доступных NS для %s", subdomain)
        return None
    except dns.exception.DNSException as exc:
        logger.debug("[takeover] DNS ошибка для %s: %s", subdomain, exc)
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Проверка уязвимости
# ──────────────────────────────────────────────────────────────────────────────

def _match_fingerprint(cname: str) -> tuple[str, dict] | None:
    """
    Находит совпадение fingerprint по CNAME target.

    Возвращает (ключ, fingerprint_dict) или None.
    Использует вхождение ключа в строку CNAME (не регулярку).
    """
    for key, fp in _TAKEOVER_FINGERPRINTS.items():
        if key in cname:
            return key, fp
    return None


def _check_takeover(subdomain: str, cname: str) -> dict | None:
    """
    Проверяет поддомен на фактическую уязвимость к Subdomain Takeover.

    Алгоритм:
    1. Ищем совпадение CNAME с известными fingerprints.
    2. Делаем GET-запрос к https://{subdomain}.
    3. Если в теле ответа найден fingerprint-текст — уязвимость подтверждена.

    Возвращает dict с результатом или None если уязвимости нет.
    """
    match = _match_fingerprint(cname)
    if match is None:
        return None

    _key, fingerprint = match

    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=_HTTP_TIMEOUT,
            verify=False,  # Сертификат на "мёртвом" поддомене может быть невалидным
            headers={"User-Agent": "EASM-TakeoverDetector/1.0"},
        ) as client:
            response = client.get(f"https://{subdomain}")

        # Ограничиваем объём текста для поиска fingerprint
        body = response.text[:_MAX_BODY_SIZE]
        error_signature = fingerprint["error_body"]

        if error_signature.lower() not in body.lower():
            # Fingerprint не найден → сервис существует, уязвимости нет
            logger.debug(
                "[takeover] %s → CNAME=%s совпадает с %s, но fingerprint не найден в теле",
                subdomain, cname, fingerprint["service"],
            )
            return None

        logger.warning(
            "[takeover] УЯЗВИМОСТЬ: %s → CNAME=%s → %s (severity=%s)",
            subdomain, cname, fingerprint["service"], fingerprint["severity"],
        )
        return {
            "subdomain": subdomain,
            "cname": cname,
            "service": fingerprint["service"],
            "severity": fingerprint["severity"],
            "fingerprint_matched": True,
        }

    except httpx.TimeoutException:
        logger.debug("[takeover] Таймаут HTTP для %s", subdomain)
    except httpx.RequestError as exc:
        logger.debug("[takeover] Сетевая ошибка для %s: %s", subdomain, exc)
    except Exception as exc:
        logger.debug("[takeover] Непредвиденная ошибка для %s: %s", subdomain, exc)

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Основная функция сканирования
# ──────────────────────────────────────────────────────────────────────────────

def scan_takeover(
    domain: str,
    subdomains: list[str],
    core_api_url: str,
    internal_secret: str,
) -> dict[str, int]:
    """
    Сканирует список поддоменов на уязвимость к Subdomain Takeover.

    Для каждого поддомена:
    1. Резолвит CNAME через DNS.
    2. Если CNAME указывает на известный уязвимый сервис — проверяет HTTP-fingerprint.
    3. При подтверждённой уязвимости создаёт событие severity=critical/high/medium.

    Отправляет события батчем через bulk_ingest.

    Возвращает {"scanned": N, "vulnerable": M, "sent": K}
    """
    if not subdomains:
        logger.info("[takeover] Список поддоменов пуст для %s, пропускаем", domain)
        return {"scanned": 0, "vulnerable": 0, "sent": 0}

    logger.info("[takeover] Проверка %d поддоменов для %s", len(subdomains), domain)

    events: list[dict] = []
    vulnerable_count = 0
    now_iso = datetime.now(timezone.utc).isoformat()

    for subdomain in subdomains:
        # Шаг 1: DNS CNAME lookup
        cname = _get_cname(subdomain)
        if cname is None:
            continue

        # Шаг 2: проверка fingerprint через HTTP
        result = _check_takeover(subdomain, cname)
        if result is None:
            continue

        # Шаг 3: создаём событие
        vulnerable_count += 1
        events.append({
            "event_type": "vulnerability",
            "severity": result["severity"],
            "source_type": "scanner",
            "source_name": "takeover_detector",
            "target_domain": domain,
            "payload": {
                "subdomain": result["subdomain"],
                "cname": result["cname"],
                "vulnerable_service": result["service"],
                "takeover_possible": True,
            },
            "detected_at": now_iso,
        })

    # Отправляем батч
    sent = 0
    if events:
        ingest_result = bulk_ingest(
            events=events,
            core_api_url=core_api_url,
            internal_secret=internal_secret,
        )
        sent = ingest_result.get("sent", 0)
        logger.info(
            "[takeover] Домен %s: проверено=%d уязвимых=%d отправлено=%d ошибок=%d",
            domain,
            len(subdomains),
            vulnerable_count,
            sent,
            ingest_result.get("errors", 0),
        )
    else:
        logger.info(
            "[takeover] Домен %s: проверено=%d уязвимых не обнаружено",
            domain,
            len(subdomains),
        )

    return {
        "scanned": len(subdomains),
        "vulnerable": vulnerable_count,
        "sent": sent,
    }
