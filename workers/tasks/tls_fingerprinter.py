"""
Воркер: TLS/JA4 fingerprinting для обнаружения WAF, прокси и теневой инфраструктуры.

JA4 = хеш от характеристик TLS Client Hello: версия, cipher suites, extensions, SNI.
Используется для идентификации клиента (браузер, curl, сканер) или инфраструктуры (WAF, CDN).
Наш фокус: получаем отпечаток СЕРВЕРА (JA4S — Server Hello), чтобы определить WAF/CDN.
"""
import hashlib
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

import httpx

from tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

# Таймаут TCP-соединения (секунды)
_CONNECT_TIMEOUT = 10

# Таймаут HTTP GET для получения заголовков (секунды)
_HTTP_TIMEOUT = 10.0

# Сколько дней до истечения сертификата считать «скоро истекает»
_CERT_EXPIRY_WARN_DAYS = 30


# ──────────────────────────────────────────────────────────────────────────────
# База WAF/CDN сигнатур
# ──────────────────────────────────────────────────────────────────────────────

_WAF_SIGNATURES: list[dict] = [
    {"name": "Cloudflare", "header": "cf-ray", "severity": "info"},
    {"name": "Cloudflare", "header": "server", "value_contains": "cloudflare", "severity": "info"},
    {"name": "AWS WAF", "header": "x-amzn-requestid", "severity": "info"},
    {"name": "AWS CloudFront", "header": "x-amz-cf-pop", "severity": "info"},
    {"name": "Akamai", "header": "x-akamai-request-id", "severity": "info"},
    {"name": "Fastly", "header": "x-served-by", "value_contains": "cache-", "severity": "info"},
    {"name": "F5 BIG-IP", "header": "x-wa-info", "severity": "medium"},
    {"name": "Imperva (Incapsula)", "header": "x-iinfo", "severity": "medium"},
    {"name": "Sucuri", "header": "x-sucuri-id", "severity": "medium"},
    {"name": "Barracuda", "header": "x-barracuda-connect", "severity": "medium"},
    # Дополнительные WAF для расширенного покрытия
    {"name": "Cloudflare", "header": "cf-cache-status", "severity": "info"},
    {"name": "AWS ALB", "header": "x-amzn-trace-id", "severity": "info"},
    {"name": "Google Cloud Armor", "header": "x-cloud-trace-context", "severity": "info"},
    {"name": "Nginx", "header": "server", "value_contains": "nginx", "severity": "info"},
    {"name": "Apache", "header": "server", "value_contains": "apache", "severity": "info"},
    {"name": "ModSecurity", "header": "x-modsec-rule-id", "severity": "medium"},
    {"name": "StackPath", "header": "x-sp-waf", "severity": "medium"},
    {"name": "Reblaze", "header": "x-reblaze-protection", "severity": "medium"},
]


def _tls_grade(version: str | None, cert_expiring_soon: bool) -> str:
    """A/B/C/F на основе версии TLS и срока сертификата."""
    if cert_expiring_soon:
        return "C"
    if version == "TLSv1.3":
        return "A"
    if version == "TLSv1.2":
        return "B"
    return "F"


# ──────────────────────────────────────────────────────────────────────────────
# TLS handshake через стандартный ssl-модуль
# ──────────────────────────────────────────────────────────────────────────────

def _get_tls_info(host: str, port: int = 443) -> dict[str, Any]:
    """
    Получает TLS-данные сервера через низкоуровневый ssl-модуль.

    Возвращает словарь с версией протокола, шифром, данными сертификата и SAN.
    При любой ошибке бросает исключение — вызывающий код его перехватывает.
    """
    context = ssl.create_default_context()

    with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()      # (name, protocol, bits) или None
            version = ssock.version()    # "TLSv1.3", "TLSv1.2", ...

            return {
                "version": version,
                "cipher_name": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "cert_subject": dict(x[0] for x in cert.get("subject", [])),
                "cert_issuer": dict(x[0] for x in cert.get("issuer", [])),
                "cert_not_after": cert.get("notAfter"),
                # subjectAltName содержит список кортежей ("DNS", "hostname")
                "san": [v for t, v in cert.get("subjectAltName", []) if t == "DNS"],
            }


# ──────────────────────────────────────────────────────────────────────────────
# WAF детектирование по HTTP-заголовкам
# ──────────────────────────────────────────────────────────────────────────────

def _detect_waf_from_headers(headers: dict[str, str]) -> list[str]:
    """
    Ищет известные WAF/CDN сигнатуры в HTTP-заголовках ответа.

    Поиск регистронезависимый. Возвращает дедуплицированный список имён WAF/CDN.
    Порядок совпадений сохраняется (первое вхождение).
    """
    # Нормализуем заголовки к нижнему регистру для регистронезависимого сравнения
    normalized: dict[str, str] = {k.lower(): v.lower() for k, v in headers.items()}

    detected: list[str] = []
    seen: set[str] = set()

    for sig in _WAF_SIGNATURES:
        header_name = sig["header"].lower()
        header_value = normalized.get(header_name)

        if header_value is None:
            continue

        # Если задан value_contains — проверяем вхождение
        required_value = sig.get("value_contains")
        if required_value and required_value.lower() not in header_value:
            continue

        name = sig["name"]
        if name not in seen:
            seen.add(name)
            detected.append(name)

    return detected


# ──────────────────────────────────────────────────────────────────────────────
# JA4S fingerprint (упрощённая реализация)
# ──────────────────────────────────────────────────────────────────────────────

def _compute_ja4s_hash(tls_info: dict[str, Any]) -> str:
    """
    Вычисляет упрощённый JA4S fingerprint сервера.

    Настоящий JA4S требует перехвата TLS Server Hello на уровне пакетов.
    Здесь используем доступные данные: версия TLS + шифр + CN издателя,
    что даёт воспроизводимый отпечаток для идентификации инфраструктуры.

    Формат: ja4s_{sha256[:12]}
    """
    tls_version = tls_info.get("version") or "unknown"
    cipher_name = tls_info.get("cipher_name") or "unknown"
    issuer_cn = tls_info.get("cert_issuer", {}).get("commonName", "unknown")

    raw = f"{tls_version}|{cipher_name}|{issuer_cn}"
    hash12 = hashlib.sha256(raw.encode()).hexdigest()[:12]
    return f"ja4s_{hash12}"


# ──────────────────────────────────────────────────────────────────────────────
# Проверка срока действия сертификата
# ──────────────────────────────────────────────────────────────────────────────

def _is_cert_expiring_soon(not_after: str | None, warn_days: int = _CERT_EXPIRY_WARN_DAYS) -> bool:
    """
    Проверяет, истекает ли сертификат в течение warn_days дней.

    not_after — строка в формате ssl-модуля: 'Dec 31 23:59:59 2024 GMT'.
    Возвращает True если до истечения меньше warn_days дней или сертификат уже просрочен.
    """
    if not not_after:
        return False

    try:
        # ssl-модуль возвращает формат openssl: 'Dec 31 23:59:59 2024 GMT'
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expiry - datetime.now(timezone.utc)).days
        return days_left < warn_days
    except (ValueError, TypeError) as exc:
        logger.debug("[tls] Не удалось распарсить дату сертификата '%s': %s", not_after, exc)
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Основная функция сканирования
# ──────────────────────────────────────────────────────────────────────────────

def run_tls_scan(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, Any]:
    """
    Выполняет TLS fingerprinting и WAF-детектирование для домена.

    Шаги:
    1. TLS handshake — получаем версию, шифр, данные сертификата.
    2. HTTP GET — получаем заголовки ответа для WAF-детектирования.
    3. Определяем WAF/CDN по сигнатурам заголовков.
    4. Вычисляем JA4S fingerprint.
    5. Проверяем срок действия сертификата.
    6. Создаём и отправляем событие через bulk_ingest.

    Возвращает dict с результатами сканирования.
    При недостижимости хоста — возвращает {"domain": domain, "error": "..."}
    """
    logger.info("[tls] Запуск TLS-сканирования для %s", domain)

    # ── Шаг 1: TLS handshake ─────────────────────────────────────────────────
    tls_info: dict[str, Any] = {}
    tls_error: str | None = None

    try:
        tls_info = _get_tls_info(domain)
        logger.debug(
            "[tls] %s: версия=%s шифр=%s",
            domain,
            tls_info.get("version"),
            tls_info.get("cipher_name"),
        )
    except ssl.SSLError as exc:
        tls_error = f"SSL ошибка: {exc}"
        logger.warning("[tls] %s: %s", domain, tls_error)
    except socket.timeout:
        tls_error = "Таймаут TCP-соединения"
        logger.warning("[tls] %s: таймаут", domain)
    except ConnectionRefusedError:
        tls_error = "Соединение отклонено (порт 443 закрыт)"
        logger.warning("[tls] %s: порт 443 закрыт", domain)
    except OSError as exc:
        tls_error = f"Сетевая ошибка: {exc}"
        logger.warning("[tls] %s: %s", domain, tls_error)
    except Exception as exc:
        tls_error = f"Непредвиденная ошибка TLS: {exc}"
        logger.warning("[tls] %s: %s", domain, tls_error)

    # Если TLS недостижим — пропускаем без события
    if tls_error and not tls_info:
        return {"domain": domain, "error": tls_error}

    # ── Шаг 2: HTTP GET для заголовков ───────────────────────────────────────
    response_headers: dict[str, str] = {}
    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=_HTTP_TIMEOUT,
            verify=False,  # TLS уже проверен ssl-модулем выше
            headers={"User-Agent": "EASM-TLSFingerprinter/1.0"},
        ) as client:
            response = client.get(f"https://{domain}")
            response_headers = dict(response.headers)
    except httpx.TimeoutException:
        logger.debug("[tls] %s: таймаут HTTP GET (заголовки пусты)", domain)
    except httpx.RequestError as exc:
        logger.debug("[tls] %s: ошибка HTTP GET: %s", domain, exc)
    except Exception as exc:
        logger.debug("[tls] %s: непредвиденная ошибка HTTP: %s", domain, exc)

    # ── Шаг 3: WAF детектирование ────────────────────────────────────────────
    waf_list = _detect_waf_from_headers(response_headers)
    if waf_list:
        logger.info("[tls] %s: обнаружены WAF/CDN: %s", domain, ", ".join(waf_list))

    # ── Шаг 4: JA4S fingerprint ──────────────────────────────────────────────
    ja4s_hash = _compute_ja4s_hash(tls_info)

    # ── Шаг 5: проверка срока сертификата ────────────────────────────────────
    cert_not_after = tls_info.get("cert_not_after")
    cert_expiring_soon = _is_cert_expiring_soon(cert_not_after)

    if cert_expiring_soon:
        logger.warning(
            "[tls] %s: сертификат истекает скоро! not_after=%s",
            domain, cert_not_after,
        )

    # ── Шаг 6: создаём и отправляем событие ──────────────────────────────────
    severity = "high" if cert_expiring_soon else "info"
    now_iso = datetime.now(timezone.utc).isoformat()

    event = {
        "event_type": "tls_fingerprint",
        "severity": severity,
        "source_type": "scanner",
        "source_name": "tls_fingerprinter",
        "target_domain": domain,
        "payload": {
            "protocol": tls_info.get("version"),
            "tls_version": tls_info.get("version"),
            "grade": _tls_grade(tls_info.get("version"), cert_expiring_soon),
            "cipher": tls_info.get("cipher_name"),
            "cipher_bits": tls_info.get("cipher_bits"),
            "waf_detected": waf_list,
            "ja4s": ja4s_hash,
            "cert_expiry": cert_not_after,
            "cert_expires": cert_not_after,
            "cert_cn": tls_info.get("cert_subject", {}).get("commonName"),
            "cert_issuer": tls_info.get("cert_issuer", {}).get("organizationName"),
            "cert_expiring_soon": cert_expiring_soon,
            "san_count": len(tls_info.get("san", [])),
        },
        "detected_at": now_iso,
    }

    ingest_result = bulk_ingest(
        events=[event],
        core_api_url=core_api_url,
        internal_secret=internal_secret,
    )
    logger.info(
        "[tls] %s: событие отправлено (sent=%d errors=%d)",
        domain,
        ingest_result.get("sent", 0),
        ingest_result.get("errors", 0),
    )

    return {
        "domain": domain,
        "tls_version": tls_info.get("version"),
        "cipher": tls_info.get("cipher_name"),
        "waf_detected": waf_list,
        "ja4s": ja4s_hash,
        "cert_expires": cert_not_after,
        "cert_expiring_soon": cert_expiring_soon,
    }
