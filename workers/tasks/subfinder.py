"""Воркер: инвентаризация поддоменов через subfinder и crt.sh."""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import httpx

from workers.celery_app import app
from workers.config import settings
from workers.tasks.base import run_tool
from workers.tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

# Таймаут HTTP-запроса к crt.sh (секунды)
_CRT_SH_TIMEOUT = 30.0

# URL шаблон для crt.sh
_CRT_SH_URL = "https://crt.sh/"

# Директория для файлов-кешей известных поддоменов
_CACHE_DIR = Path("/tmp")


def _cache_path(domain: str) -> Path:
    """Возвращает путь к файлу-кешу известных поддоменов для домена."""
    # Нормализуем имя файла: только буквы, цифры, дефис и точка
    safe = "".join(c if (c.isalnum() or c in ".-") else "_" for c in domain.lower())
    return _CACHE_DIR / f"known_{safe}_subdomains.txt"


def _load_known_subdomains(domain: str) -> set[str] | None:
    """
    Загружает кеш известных поддоменов из файла.

    Возвращает set строк если файл существует, иначе None
    (первый запуск — не создаём шум).
    """
    path = _cache_path(domain)
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8")
        return {line.strip().lower() for line in text.splitlines() if line.strip()}
    except OSError as exc:
        logger.warning("[subfinder] Не удалось прочитать кеш поддоменов %s: %s", path, exc)
        return None


def _save_known_subdomains(domain: str, subdomains: set[str]) -> None:
    """Атомарно сохраняет обновлённый кеш поддоменов в файл."""
    path = _cache_path(domain)
    try:
        # Записываем во временный файл, затем переименовываем — атомарная операция
        tmp = path.with_suffix(".tmp")
        tmp.write_text("\n".join(sorted(subdomains)), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        logger.warning("[subfinder] Не удалось сохранить кеш поддоменов %s: %s", path, exc)


def check_asset_drift(subdomains: list[str], domain: str) -> list[str]:
    """
    Определяет новые поддомены по сравнению с кешем предыдущего запуска.

    Логика:
    - Файл НЕ существует → первый запуск → все поддомены «известные»
      (severity="info"), кеш создаётся для следующего запуска.
    - Файл существует → сравниваем с кешем; поддомены отсутствующие
      в кеше считаются новыми активами (severity="medium").

    Обновляет файл кеша в конце независимо от результата.

    Возвращает список поддоменов, которые являются новыми (пустой при первом запуске).
    """
    known = _load_known_subdomains(domain)
    subdomain_set = {s.lower() for s in subdomains}

    if known is None:
        # Первый запуск — сохраняем кеш, не сигнализируем о «новых»
        logger.info(
            "[subfinder] Первый запуск для %s — создаём кеш из %d поддоменов",
            domain, len(subdomain_set),
        )
        _save_known_subdomains(domain, subdomain_set)
        return []

    new_assets = [s for s in subdomains if s.lower() not in known]

    if new_assets:
        logger.info(
            "[subfinder] Asset drift: %d новых поддоменов для %s: %s",
            len(new_assets), domain, new_assets[:5],
        )
        # Обновляем кеш — добавляем новые поддомены
        _save_known_subdomains(domain, known | subdomain_set)
    else:
        logger.debug("[subfinder] Asset drift: новых поддоменов для %s не обнаружено", domain)

    return new_assets


def fetch_crt_sh(domain: str) -> list[str]:
    """
    Запрашивает сертификатную прозрачность crt.sh для домена.

    Делает GET https://crt.sh/?q=%.{domain}&output=json,
    извлекает поле name_value, дедублицирует и отфильтровывает
    wildcard-записи (начинающиеся с '*').

    Возвращает отсортированный список уникальных поддоменов.
    При любой ошибке (сеть, таймаут, невалидный JSON) возвращает
    пустой список — graceful degradation.
    """
    params = {"q": f"%.{domain}", "output": "json"}
    try:
        response = httpx.get(_CRT_SH_URL, params=params, timeout=_CRT_SH_TIMEOUT)
        response.raise_for_status()
    except httpx.TimeoutException:
        logger.warning("crt.sh: таймаут запроса для домена %s", domain)
        return []
    except httpx.HTTPStatusError as exc:
        logger.warning("crt.sh: HTTP ошибка %d для домена %s", exc.response.status_code, domain)
        return []
    except httpx.RequestError as exc:
        logger.warning("crt.sh: ошибка сети для домена %s: %s", domain, exc)
        return []

    try:
        records = response.json()
    except json.JSONDecodeError as exc:
        logger.warning("crt.sh: невалидный JSON для домена %s: %s", domain, exc)
        return []

    # Извлекаем name_value, разбиваем по переносам (crt.sh может вернуть
    # несколько имён в одном поле через \n), убираем wildcard и дубли
    seen: set[str] = set()
    result: list[str] = []
    for record in records:
        raw_value = record.get("name_value", "")
        # name_value может содержать несколько имён через перенос строки
        for name in raw_value.splitlines():
            name = name.strip().lower()
            # Пропускаем пустые строки и wildcard-записи
            if not name or name.startswith("*"):
                continue
            if name not in seen:
                seen.add(name)
                result.append(name)

    logger.info("crt.sh: найдено %d уникальных поддоменов для %s", len(result), domain)
    return sorted(result)


@app.task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    name="workers.tasks.subfinder.scan_domain",
)
def scan_domain(self, domain: str) -> dict:
    """
    Запускает subfinder для обнаружения поддоменов.
    Каждый найденный поддомен отправляется как отдельное NormalizedEvent.
    После завершения ставит в очередь nuclei-сканирование каждого поддомена.
    """
    logger.info("Запуск subfinder для домена: %s", domain)

    try:
        stdout, stderr = run_tool(
            [settings.SUBFINDER_BIN, "-d", domain, "-silent", "-json"],
            timeout=120,
        )
    except RuntimeError as exc:
        logger.error("subfinder завершился с ошибкой: %s", exc)
        raise self.retry(exc=exc)

    sent = 0
    subdomains: list[str] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # subfinder иногда выдаёт просто hostname без JSON
            record = {"host": line}

        subdomain = record.get("host", "")
        if not subdomain:
            continue

        subdomains.append(subdomain)

    # ── Asset Drift Detection ─────────────────────────────────────────────────
    # Определяем какие поддомены новые относительно предыдущего скана.
    # Первый запуск (кеш-файл отсутствует): все «известные» (severity="info").
    # Последующие запуски: новые поддомены → severity="medium".
    # Флаг is_first_run нужен crt.sh-блоку ниже.
    is_first_run = _load_known_subdomains(domain) is None
    try:
        new_assets = check_asset_drift(subdomains, domain)
        new_asset_set: set[str] = {s.lower() for s in new_assets}
    except Exception as exc:
        logger.error("[subfinder] Ошибка asset drift check: %s", exc)
        new_assets = []
        new_asset_set = set()

    # Отправляем события для всех поддоменов subfinder батчем
    now_iso = datetime.now(timezone.utc).isoformat()
    subfinder_events = [
        {
            "event_type": "subdomain",
            "severity": "medium" if subdomain_item.lower() in new_asset_set else "info",
            "source_type": "subfinder",
            "source_name": "subfinder",
            "target_domain": domain,
            "payload": {
                "subdomain": subdomain_item,
                "new_asset": subdomain_item.lower() in new_asset_set,
            },
            "detected_at": now_iso,
        }
        for subdomain_item in subdomains
    ]

    if subfinder_events:
        ingest_result = bulk_ingest(
            events=subfinder_events,
            core_api_url=settings.CORE_API_URL,
            internal_secret=settings.INTERNAL_API_SECRET,
        )
        sent = ingest_result.get("sent", 0)
        logger.info(
            "subfinder: отправлено %d событий для %s (новых активов: %d, ошибок: %d)",
            sent, domain, len(new_assets),
            ingest_result.get("errors", 0),
        )
    else:
        logger.info("subfinder: поддоменов не найдено для %s", domain)
    # ─────────────────────────────────────────────────────────────────────────

    # ── Обогащение через crt.sh (задача 8.A.1 / 8.A.2) ──────────────────────
    # Ошибка crt.sh не должна ломать основной скан: весь блок обёрнут в try/except
    try:
        crt_subdomains = fetch_crt_sh(domain)

        # Отфильтровываем поддомены, которые subfinder уже нашёл
        subfinder_set = set(subdomains)
        new_from_crt = [s for s in crt_subdomains if s not in subfinder_set]

        if new_from_crt:
            crt_new_set: set[str] = {s.lower() for s in new_from_crt}

            # Drift detection для crt.sh: проверяем актуальный кеш
            # (он уже обновлён subfinder-поддоменами выше).
            # new_asset_set (из subfinder) не перекрывает crt.sh-уникальные поддомены,
            # поэтому читаем кеш заново и проверяем напрямую.
            try:
                known_after_subfinder = _load_known_subdomains(domain) or set()
                # Поддомен «новый» если его нет в обновлённом кеше
                crt_newly_seen: set[str] = crt_new_set - known_after_subfinder
                # Сохраняем новые crt.sh поддомены в кеш
                if crt_newly_seen:
                    _save_known_subdomains(domain, known_after_subfinder | crt_new_set)
            except Exception as cache_exc:
                logger.debug("[subfinder] Не удалось обновить кеш для crt.sh: %s", cache_exc)
                # При ошибке кеша: если first_run (new_asset_set пуст) → info, иначе → medium для всех
                crt_newly_seen = set() if not new_asset_set else crt_new_set

            # Первый запуск (кеш не существовал до этого скана) → всё severity="info"
            crt_events = [
                {
                    "event_type": "subdomain",
                    "severity": "info" if is_first_run else (
                        "medium" if sub.lower() in crt_newly_seen else "info"
                    ),
                    "source_type": "crt.sh",
                    "source_name": "crt.sh",
                    "target_domain": domain,
                    "payload": {
                        "subdomain": sub,
                        "new_asset": not is_first_run and sub.lower() in crt_newly_seen,
                    },
                    "detected_at": now_iso,
                }
                for sub in new_from_crt
            ]

            ingest_result = bulk_ingest(
                events=crt_events,
                core_api_url=settings.CORE_API_URL,
                internal_secret=settings.INTERNAL_API_SECRET,
            )
            logger.info(
                "crt.sh: отправлено %d новых поддоменов для %s (ошибок: %d)",
                ingest_result.get("sent", 0),
                domain,
                ingest_result.get("errors", 0),
            )

            # Добавляем новые поддомены в общий список для nuclei
            subdomains.extend(new_from_crt)
        else:
            logger.info("crt.sh: новых поддоменов для %s не найдено", domain)

    except Exception as exc:
        # Любая непредвиденная ошибка не ломает основной скан
        logger.error("crt.sh: неожиданная ошибка при обработке домена %s: %s", domain, exc)
    # ─────────────────────────────────────────────────────────────────────────

    # Ставим задачи nuclei в очередь для каждого поддомена
    # Импортируем здесь чтобы избежать циклического импорта
    from workers.tasks.nuclei import scan_target
    for subdomain in subdomains:
        scan_target.apply_async(
            args=[subdomain, domain],
            queue="scanning",
        )
    logger.info("subfinder: поставлено %d nuclei-задач для %s", len(subdomains), domain)

    return {"domain": domain, "subdomains_sent": sent, "nuclei_queued": len(subdomains)}


@app.task(
    bind=True,
    name="workers.tasks.subfinder.scan_domain_all_active",
    ignore_result=True,
)
def scan_domain_all_active(self) -> None:
    """
    Периодическая задача (запускается Celery Beat раз в сутки).
    Опрашивает Core API за списком активных активов и ставит в очередь
    scan_domain для каждого.
    """
    import httpx

    logger.info("Запуск плановой переинвентаризации всех активных доменов")
    url = f"{settings.CORE_API_URL}/api/v1/assets/"
    headers = {"Authorization": f"Bearer {settings.INTERNAL_API_SECRET}"}

    try:
        response = httpx.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        assets = response.json()
    except Exception as exc:
        logger.error("Не удалось получить список активов: %s", exc)
        return

    queued = 0
    for asset in assets:
        if asset.get("is_active"):
            scan_domain.apply_async(args=[asset["domain"]], queue="discovery")
            queued += 1

    logger.info("Плановая переинвентаризация: поставлено %d доменов в очередь", queued)
