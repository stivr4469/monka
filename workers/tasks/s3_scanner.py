"""Воркер: обнаружение открытых/существующих S3-корзин по имени компании из домена."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

import httpx

from workers.tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

# Таймаут HEAD/GET запроса (секунды)
_REQUEST_TIMEOUT = 10

# Максимальный параллелизм при проверке бакетов
_MAX_WORKERS = 20

# URL-шаблон для S3 virtual-hosted style
_S3_URL_TEMPLATE = "https://{bucket}.s3.amazonaws.com"

# Маркер открытого листинга в теле ответа
_LISTING_MARKER = b"<ListBucketResult"


def _generate_bucket_names(company: str) -> list[str]:
    """
    Генерирует список кандидатов имён S3-бакетов на основе имени компании.

    company — первая часть домена, уже приведённая к нижнему регистру
    (например "target" из "target.com").

    Возвращает дедуплицированный список, сохраняя порядок (наиболее
    «горячие» шаблоны идут первыми).
    """
    # Только ASCII-буквы, цифры и дефисы допустимы в именах S3-бакетов.
    # Нормализуем: убираем всё, что не подходит.
    safe = "".join(c if (c.isalnum() or c == "-") else "-" for c in company.lower()).strip("-")
    if not safe:
        return []

    environments = ["prod", "production", "dev", "staging", "test", "uat", "qa", "demo"]
    data_types = [
        "backup", "backups", "data", "assets", "logs", "media",
        "static", "files", "uploads", "export", "dump", "archive",
        "images", "documents", "reports", "config", "secrets", "storage",
    ]

    seen: set[str] = set()
    names: list[str] = []

    def _add(name: str) -> None:
        # Имена S3 должны быть 3–63 символа, начинаться с буквы/цифры,
        # не заканчиваться дефисом, не содержать «..» или «.-»
        cleaned = name.strip("-").lower()
        if not cleaned or len(cleaned) < 3 or len(cleaned) > 63:
            return
        if cleaned in seen:
            return
        seen.add(cleaned)
        names.append(cleaned)

    # Уровень 1: базовые имена
    _add(safe)
    _add(f"{safe}-s3")
    _add(f"s3-{safe}")

    # Уровень 2: company + env
    for env in environments:
        _add(f"{safe}-{env}")
        _add(f"{env}-{safe}")
        _add(f"{safe}{env}")           # без дефиса: "targetprod"

    # Уровень 3: company + data_type
    for dtype in data_types:
        _add(f"{safe}-{dtype}")
        _add(f"{dtype}-{safe}")
        _add(f"{safe}{dtype}")         # без дефиса: "targetbackup"

    # Уровень 4: company + env + data_type
    for env in environments:
        for dtype in data_types:
            _add(f"{safe}-{env}-{dtype}")
            _add(f"{env}-{safe}-{dtype}")

    logger.debug("[s3_scanner] Сгенерировано %d паттернов для '%s'", len(names), safe)
    return names


def _check_bucket(bucket_name: str, client: httpx.Client) -> dict[str, Any] | None:
    """
    Проверяет существование и доступность S3-бакета.

    Алгоритм:
    1. HEAD-запрос — определяем, существует ли бакет.
       200 или 403 → существует; иначе → не существует (пропускаем).
    2. Если существует: GET-запрос.
       200 + тело содержит <ListBucketResult → ОТКРЫТЫЙ бакет.
       403 → существует, но закрытый.

    Возвращает dict или None (бакет не существует / ошибка DNS).
    """
    url = _S3_URL_TEMPLATE.format(bucket=bucket_name)
    region: str | None = None

    try:
        head = client.head(url)
        region = head.headers.get("x-amz-bucket-region")

        if head.status_code not in (200, 403, 301, 302, 307, 308):
            # 404, 400 — бакет не существует
            return None

    except (httpx.ConnectError, httpx.ConnectTimeout):
        # DNS NXDOMAIN или недоступен — пропускаем без события
        return None
    except httpx.TimeoutException:
        logger.debug("[s3_scanner] Таймаут HEAD для бакета: %s", bucket_name)
        return None
    except httpx.RequestError as exc:
        logger.debug("[s3_scanner] Ошибка HEAD для '%s': %s", bucket_name, exc)
        return None

    # Бакет существует — пробуем GET для проверки листинга
    accessible = False
    try:
        get = client.get(url)
        if get.status_code == 200 and _LISTING_MARKER in get.content[:512]:
            accessible = True
        if not region:
            region = get.headers.get("x-amz-bucket-region")
    except (httpx.RequestError, httpx.TimeoutException) as exc:
        logger.debug("[s3_scanner] Ошибка GET для '%s': %s", bucket_name, exc)
        # Бакет существует (HEAD прошёл), но GET упал — считаем закрытым

    return {
        "bucket": bucket_name,
        "accessible": accessible,
        "region": region,
    }


def run_s3_scan(domain: str, core_api_url: str, internal_secret: str) -> dict[str, Any]:
    """
    Основная точка входа S3-сканирования.

    1. Генерирует имена бакетов по имени компании из домена.
    2. Проверяет каждый параллельно через _check_bucket.
    3. Формирует события NormalizedEvent и отправляет через bulk_ingest.
    4. Возвращает сводную статистику.
    """
    # Извлекаем имя компании: "target.com" → "target"
    company = domain.split(".")[0].lower()
    logger.info("[s3_scanner] Запуск для домена=%s company=%s", domain, company)

    bucket_names = _generate_bucket_names(company)
    if not bucket_names:
        logger.warning("[s3_scanner] Не удалось сгенерировать имена для company='%s'", company)
        return {"domain": domain, "checked": 0, "found": 0, "accessible": 0}

    found: list[dict[str, Any]] = []
    checked = 0

    # Единый httpx.Client с короткими таймаутами и без авто-редиректов
    limits = httpx.Limits(max_connections=_MAX_WORKERS, max_keepalive_connections=_MAX_WORKERS)
    timeout = httpx.Timeout(connect=5.0, read=_REQUEST_TIMEOUT, write=5.0, pool=5.0)

    with httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        limits=limits,
        headers={"User-Agent": "EASM-Scanner/1.0"},
    ) as client:
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="s3_check") as pool:
            futures = {pool.submit(_check_bucket, name, client): name for name in bucket_names}
            for future in as_completed(futures):
                checked += 1
                try:
                    result = future.result()
                except Exception as exc:
                    logger.debug("[s3_scanner] Неожиданная ошибка воркера: %s", exc)
                    continue
                if result is not None:
                    found.append(result)

    accessible_count = sum(1 for r in found if r["accessible"])
    logger.info(
        "[s3_scanner] Проверено=%d найдено=%d открытых=%d для %s",
        checked, len(found), accessible_count, domain,
    )

    if not found:
        return {"domain": domain, "checked": checked, "found": 0, "accessible": 0}

    # Формируем события
    now_iso = datetime.now(timezone.utc).isoformat()
    events: list[dict[str, Any]] = []
    for result in found:
        severity = "critical" if result["accessible"] else "medium"
        events.append({
            "event_type": "exposed_service",
            "severity": severity,
            "source_type": "scanner",
            "source_name": "s3_scanner",
            "target_domain": domain,
            "payload": {
                "bucket": result["bucket"],
                "accessible": result["accessible"],
                "region": result["region"],
                "url": _S3_URL_TEMPLATE.format(bucket=result["bucket"]),
            },
            "detected_at": now_iso,
        })

    ingest_result = bulk_ingest(
        events=events,
        core_api_url=core_api_url,
        internal_secret=internal_secret,
    )
    logger.info(
        "[s3_scanner] Отправлено событий: %d (ошибок: %d)",
        ingest_result.get("sent", 0),
        ingest_result.get("errors", 0),
    )

    return {
        "domain": domain,
        "checked": checked,
        "found": len(found),
        "accessible": accessible_count,
    }
