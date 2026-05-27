"""
Воркер: поиск утечек секретов в GitHub-репозиториях через gitleaks.

Архитектура:
  install_gitleaks()         — разовая установка бинарника из GitHub Releases
  scan_github_repo()         — клонирование + сканирование одного репозитория
  scan_github_results()      — оркестратор: поиск репозиториев → mass-scan
  scan_repo (Celery-задача)  — обёртка для асинхронного запуска через Celery
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from workers.crypto import encrypt_password

logger = logging.getLogger(__name__)

# Celery-импорты ленивые — без них модуль можно импортировать в тестовом окружении
# где Celery/Redis недоступны. Декоратор @app.task подключается через try/except.
try:
    from workers.celery_app import app as _celery_app
    from workers.config import settings as _worker_settings
    _CELERY_AVAILABLE = True
except ImportError:
    _celery_app = None  # type: ignore[assignment]
    _worker_settings = None  # type: ignore[assignment]
    _CELERY_AVAILABLE = False


# ─── Константы ────────────────────────────────────────────────────────────────

GITLEAKS_BIN_PATH = Path("/tmp/gitleaks")
GITLEAKS_RELEASES_API = "https://api.github.com/repos/gitleaks/gitleaks/releases/latest"
GITLEAKS_ASSET_PATTERN = "linux_x64"

# Временная директория для клонирования репозиториев
CLONE_BASE = Path("/tmp/gitleaks_scan")

# FP-фильтр для репозиториев
_FP_REPO_RE = re.compile(
    r"(?i)"
    # Списки доменов / исследовательские датасеты
    r"tranco|domain.?list|rank.?list|tld.?list|whois.?data"
    r"|crawl.?data|pii.?xel|piidb|privadb|randomwebsite"
    r"|web.?crawl|site.?mirror|domain.?scan|nextlist"
    r"|reviewnav.?handler|alexa.?top|majestic.?million"
    r"|tracking.?pixel|pixel.?track"
    r"|top[\-_]?\d+k?|alexa|majestic|umbrella"
    # SMS-бомберы, спам-инструменты, атак-утилиты
    r"|sms.?bomb|sms.?attack|sms.?spam|sms.?flood|smsbom|smsham"
    r"|maxwell.?spammer|spammer|b0mb3r|bomber|flooder|ddoser"
    r"|rkr0k3|wit.?tools|telebotpy|iisus|spymer"
    r"|apk.?anti|email.?bomb|tgsb"
    # Списки истёкших доменов
    r"|expired.?domain|domain.?names.?by.?day"
    # Специфичные GitHub-аккаунты атакеров/спамеров
    r"|antichristone|umutkara.?tools|imasender"
)


def _is_fp_repo(repo_url: str) -> bool:
    """Возвращает True если репозиторий — явный false positive (domain-list, research)."""
    repo_name = repo_url.rstrip("/").split("/")[-1]
    return bool(_FP_REPO_RE.search(repo_name) or _FP_REPO_RE.search(repo_url))

# Rate-limit GitHub: не более 10 запросов поиска в минуту
GITHUB_SEARCH_URL = "https://api.github.com/search/code"
GITHUB_SEARCH_QUERIES = [
    '"{domain}" password',
    '"{domain}" secret',
    '"{domain}" api_key',
    '"{domain}" token',
    '"{domain}" extension:env',
]


# ─── Маскировка секрета ───────────────────────────────────────────────────────

def _mask_secret(value: str, visible_prefix: int = 4) -> str:
    """
    Маскирует секрет: первые visible_prefix символов + '***'.
    Никогда не возвращаем полное значение.
    """
    if not value:
        return "***"
    if len(value) <= visible_prefix:
        return "***"
    return value[:visible_prefix] + "***"


# ─── Установка gitleaks ───────────────────────────────────────────────────────

def install_gitleaks() -> str | None:
    """
    Проверяет наличие /tmp/gitleaks.
    Если бинарника нет — скачивает последний релиз linux_x64 через GitHub API,
    распаковывает tar.gz и устанавливает в /tmp/gitleaks.

    Возвращает путь к бинарнику или None при ошибке.
    """
    # Используем настроенный путь из конфигурации если он существует
    if _worker_settings is not None:
        configured_bin = Path(_worker_settings.GITLEAKS_BIN)
        if configured_bin.exists() and os.access(configured_bin, os.X_OK):
            logger.info("gitleaks найден по настроенному пути: %s", configured_bin)
            return str(configured_bin)

    # Fallback: проверяем /tmp/gitleaks
    if GITLEAKS_BIN_PATH.exists() and os.access(GITLEAKS_BIN_PATH, os.X_OK):
        logger.info("gitleaks найден: %s", GITLEAKS_BIN_PATH)
        return str(GITLEAKS_BIN_PATH)

    logger.info("gitleaks не найден, начинаю загрузку...")

    try:
        # Получаем метаданные последнего релиза
        resp = httpx.get(
            GITLEAKS_RELEASES_API,
            headers={"Accept": "application/vnd.github+json"},
            timeout=15.0,
        )
        resp.raise_for_status()
        release = resp.json()
    except Exception as exc:
        logger.error("Не удалось получить метаданные релиза gitleaks: %s", exc)
        return None

    # Ищем подходящий asset для linux_x64
    asset_url: str | None = None
    for asset in release.get("assets", []):
        name: str = asset.get("name", "")
        if GITLEAKS_ASSET_PATTERN in name and name.endswith(".tar.gz"):
            asset_url = asset.get("browser_download_url")
            break

    if not asset_url:
        logger.error(
            "Не нашёл asset '%s' в релизе gitleaks %s",
            GITLEAKS_ASSET_PATTERN,
            release.get("tag_name", "?"),
        )
        return None

    logger.info("Скачиваю gitleaks: %s", asset_url)

    try:
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp_file:
            tmp_path = Path(tmp_file.name)
            with httpx.stream("GET", asset_url, follow_redirects=True, timeout=60.0) as stream:
                stream.raise_for_status()
                for chunk in stream.iter_bytes(chunk_size=8192):
                    tmp_file.write(chunk)
    except Exception as exc:
        logger.error("Ошибка загрузки gitleaks: %s", exc)
        tmp_path.unlink(missing_ok=True)
        return None

    try:
        with tarfile.open(tmp_path, "r:gz") as tar:
            # Извлекаем только бинарник gitleaks, игнорируем остальные файлы
            members = [m for m in tar.getmembers() if m.name in ("gitleaks", "./gitleaks")]
            if not members:
                # Если имя отличается, берём первый исполняемый файл
                members = [m for m in tar.getmembers() if not m.isdir()]

            if not members:
                logger.error("В архиве gitleaks не найден бинарник")
                return None

            member = members[0]
            # Защита от TarSlip: убираем все компоненты пути, оставляем только имя файла
            member.name = Path(member.name).name or "gitleaks"
            if member.name != "gitleaks":
                member.name = "gitleaks"  # нормализуем имя бинарника
            try:
                tar.extract(member, path=Path("/tmp"), set_attrs=False, filter="data")
            except TypeError:
                # Python < 3.12 не поддерживает filter=
                tar.extract(member, path=Path("/tmp"), set_attrs=False)
    except Exception as exc:
        logger.error("Ошибка распаковки gitleaks: %s", exc)
        return None
    finally:
        tmp_path.unlink(missing_ok=True)

    try:
        GITLEAKS_BIN_PATH.chmod(0o755)
    except OSError as exc:
        logger.error("Не удалось сделать gitleaks исполняемым: %s", exc)
        return None

    logger.info("gitleaks успешно установлен: %s", GITLEAKS_BIN_PATH)
    return str(GITLEAKS_BIN_PATH)


# ─── Сканирование одного репозитория ─────────────────────────────────────────

def scan_github_repo(
    repo_url: str,
    domain: str,
    core_api_url: str,
    internal_secret: str,
    gitleaks_bin: str | None = None,
) -> dict[str, Any]:
    """
    Клонирует репозиторий и запускает gitleaks.
    Секреты маскируются ПЕРЕД отправкой.

    Аргументы:
        repo_url        — HTTPS URL репозитория (https://github.com/org/repo)
        domain          — корневой домен для привязки событий
        core_api_url    — URL Core API (например http://core:8000)
        internal_secret — shared secret для /ingest
        gitleaks_bin    — путь к бинарнику (None → install_gitleaks())

    Возвращает: {"repo": repo_url, "secrets_found": N, "sent": K}
    """
    # Определяем путь к бинарнику
    bin_path = gitleaks_bin or install_gitleaks()
    if not bin_path:
        logger.error("gitleaks не установлен, сканирование %s невозможно", repo_url)
        return {"repo": repo_url, "secrets_found": 0, "sent": 0, "error": "gitleaks not available"}

    # Имя директории из URL: https://github.com/org/repo → org_repo
    parsed = urlparse(repo_url)
    repo_slug = parsed.path.strip("/").replace("/", "_")
    if not repo_slug:
        repo_slug = "unknown_repo"

    clone_dir = CLONE_BASE / repo_slug
    CLONE_BASE.mkdir(parents=True, exist_ok=True)

    secrets_found = 0
    sent = 0

    try:
        # Клонируем с минимальной глубиной для экономии времени и места
        _clone_repo(repo_url, clone_dir)

        # Запускаем gitleaks с JSON-отчётом
        report_path = clone_dir / "gl_report.json"
        secrets_found, sent = _run_gitleaks(
            bin_path=bin_path,
            source_dir=clone_dir,
            report_path=report_path,
            repo_url=repo_url,
            domain=domain,
            core_api_url=core_api_url,
            internal_secret=internal_secret,
        )

    except _CloneError as exc:
        logger.error("Не удалось клонировать %s: %s", repo_url, exc)
        return {"repo": repo_url, "secrets_found": 0, "sent": 0, "error": str(exc)}

    finally:
        # ВСЕГДА удаляем клонированный репозиторий
        if clone_dir.exists():
            try:
                shutil.rmtree(clone_dir)
                logger.debug("Удалена временная директория: %s", clone_dir)
            except OSError as exc:
                logger.warning("Не удалось удалить %s: %s", clone_dir, exc)

    logger.info(
        "gitleaks: repo=%s secrets_found=%d sent=%d",
        repo_url,
        secrets_found,
        sent,
    )
    return {"repo": repo_url, "secrets_found": secrets_found, "sent": sent}


class _CloneError(RuntimeError):
    """Ошибка клонирования репозитория."""


def _clone_repo(repo_url: str, target_dir: Path) -> None:
    """Клонирует репозиторий с глубиной 50 коммитов."""
    if target_dir.exists():
        shutil.rmtree(target_dir)

    try:
        result = subprocess.run(
            ["git", "clone", "--depth=10", "--quiet", repo_url, str(target_dir)],
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,  # ОБЯЗАТЕЛЬНО False — защита от инъекций
        )
    except subprocess.TimeoutExpired:
        raise _CloneError(f"Таймаут клонирования {repo_url} (30s)")
    except FileNotFoundError:
        raise _CloneError("git не установлен")
    except OSError as exc:
        raise _CloneError(f"OSError при клонировании: {exc}") from exc

    if result.returncode != 0:
        stderr = result.stderr.strip()[:500]  # ограничиваем длину для логов
        raise _CloneError(f"git clone вернул код {result.returncode}: {stderr}")


def _run_gitleaks(
    bin_path: str,
    source_dir: Path,
    report_path: Path,
    repo_url: str,
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> tuple[int, int]:
    """
    Запускает gitleaks detect и отправляет находки в Core API.
    Возвращает (secrets_found, sent).
    """
    try:
        result = subprocess.run(
            [
                bin_path,
                "detect",
                f"--source={source_dir}",
                "--report-format=json",
                f"--report-path={report_path}",
                "--no-git",
                "--exit-code=0",   # 0 даже при находках — контролируем сами
            ],
            capture_output=True,
            text=True,
            timeout=90,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("Таймаут gitleaks для %s", repo_url)
        return 0, 0
    except (FileNotFoundError, OSError) as exc:
        logger.error("Ошибка запуска gitleaks: %s", exc)
        return 0, 0

    if result.returncode not in (0, 1):
        # gitleaks возвращает 1 если нашёл секреты (при --exit-code=0 этого не должно быть)
        logger.warning(
            "gitleaks завершился с кодом %d для %s: %s",
            result.returncode,
            repo_url,
            result.stderr[:300],
        )

    if not report_path.exists():
        logger.info("gitleaks: отчёт не создан для %s (утечек нет)", repo_url)
        return 0, 0

    try:
        raw = report_path.read_text(encoding="utf-8")
        findings: list[dict] = json.loads(raw) if raw.strip() else []
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Не удалось прочитать отчёт gitleaks: %s", exc)
        return 0, 0

    if not findings:
        return 0, 0

    secrets_found = len(findings)
    sent = _send_findings(
        findings=findings,
        repo_url=repo_url,
        domain=domain,
        core_api_url=core_api_url,
        internal_secret=internal_secret,
    )
    return secrets_found, sent


def _send_findings(
    findings: list[dict],
    repo_url: str,
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> int:
    """Отправляет находки gitleaks в Core API. Возвращает количество успешно отправленных."""
    ingest_url = f"{core_api_url.rstrip('/')}/api/v1/internal/ingest"
    headers = {"Authorization": f"Bearer {internal_secret}"}
    sent = 0

    for finding in findings:
        raw_secret = finding.get("Secret", "") or finding.get("Match", "")
        masked = _mask_secret(raw_secret)
        enc = encrypt_password(raw_secret, internal_secret) if raw_secret else ""

        # Определяем тип секрета из rule ID
        rule_id = finding.get("RuleID", "")
        secret_type = _classify_secret_type(rule_id)

        event: dict[str, Any] = {
            "event_type": "secret_leak",
            "severity": "critical",
            "source_type": "gitleaks",
            "source_name": "gitleaks",
            "target_domain": domain,
            "payload": {
                "repo_url": repo_url,
                "rule_id": rule_id,
                "secret_type": secret_type,
                "file": finding.get("File", ""),
                "line": finding.get("StartLine", 0),
                "commit": finding.get("Commit", ""),
                "author": finding.get("Author", ""),
                "date": finding.get("Date", ""),
                "secret_masked": masked,
                "secret_enc": enc,  # Fernet-шифрование; raw_secret НЕ хранится
            },
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            resp = httpx.post(ingest_url, json=event, headers=headers, timeout=10.0)
            status = resp.json().get("status", "error")
            if status in ("accepted", "duplicate"):
                sent += 1
            else:
                logger.warning("Core API отклонил событие gitleaks: status=%s", status)
        except Exception as exc:
            logger.warning("Не удалось отправить событие gitleaks: %s", exc)

    return sent


def _classify_secret_type(rule_id: str) -> str:
    """Классифицирует тип секрета по rule_id gitleaks."""
    rule_lower = rule_id.lower()
    if "aws" in rule_lower:
        return "aws_credentials"
    if "github" in rule_lower:
        return "github_token"
    if "google" in rule_lower:
        return "google_api_key"
    if "stripe" in rule_lower:
        return "stripe_key"
    if "slack" in rule_lower:
        return "slack_token"
    if "jwt" in rule_lower:
        return "jwt_token"
    if "private" in rule_lower and "key" in rule_lower:
        return "private_key"
    if "password" in rule_lower:
        return "password"
    if "api" in rule_lower and "key" in rule_lower:
        return "api_key"
    return "generic_secret"


# ─── Оркестратор: обход всех репозиториев домена ─────────────────────────────

def scan_github_results(
    domain: str,
    github_token: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, Any]:
    """
    Находит репозитории упоминающие домен через GitHub Search API,
    затем запускает gitleaks против каждого уникального репозитория.

    Возвращает: {"repos_scanned": N, "total_secrets": M, "sent": K}
    """
    # Устанавливаем gitleaks заранее (один раз)
    gitleaks_bin = install_gitleaks()
    if not gitleaks_bin:
        logger.error("gitleaks недоступен, сканирование отменено")
        return {"repos_scanned": 0, "total_secrets": 0, "sent": 0, "error": "gitleaks not available"}

    # Собираем уникальные репозитории через GitHub Search
    repo_urls, fp_filtered = _collect_repos_from_search(domain, github_token)

    if not repo_urls:
        logger.info("Не найдено репозиториев для домена %s", domain)
        return {"repos_scanned": 0, "total_secrets": 0, "sent": 0, "fp_filtered": fp_filtered}

    logger.info(
        "Найдено %d уникальных репозиториев для %s (отфильтровано FP: %d)",
        len(repo_urls), domain, fp_filtered,
    )

    repos_scanned = 0
    total_secrets = 0
    total_sent = 0

    for repo_url in repo_urls:
        result = scan_github_repo(
            repo_url=repo_url,
            domain=domain,
            core_api_url=core_api_url,
            internal_secret=internal_secret,
            gitleaks_bin=gitleaks_bin,
        )
        repos_scanned += 1
        total_secrets += result.get("secrets_found", 0)
        total_sent += result.get("sent", 0)

    logger.info(
        "gitleaks scan_github_results: domain=%s repos=%d secrets=%d sent=%d fp_filtered=%d",
        domain, repos_scanned, total_secrets, total_sent, fp_filtered,
    )
    return {
        "repos_scanned": repos_scanned,
        "total_secrets": total_secrets,
        "sent":          total_sent,
        "fp_filtered":   fp_filtered,
    }


def _collect_repos_from_search(domain: str, github_token: str) -> tuple[set[str], int]:
    """
    Использует GitHub Search API для поиска репозиториев упоминающих домен.
    Возвращает (множество HTML-URL репозиториев, количество отфильтрованных FP).
    """
    headers: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    repo_urls: set[str] = set()
    fp_filtered = 0

    for query_tpl in GITHUB_SEARCH_QUERIES:
        query = query_tpl.format(domain=domain)
        try:
            resp = httpx.get(
                GITHUB_SEARCH_URL,
                params={"q": query, "per_page": 30, "sort": "indexed", "order": "desc"},
                headers=headers,
                timeout=15.0,
            )
            if resp.status_code == 403:
                logger.warning("GitHub rate limit при поиске репозиториев, пропускаю")
                continue
            if resp.status_code != 200:
                logger.warning("GitHub Search вернул %d для '%s'", resp.status_code, query)
                continue

            items = resp.json().get("items", [])
            for item in items:
                repo_html_url = item.get("repository", {}).get("html_url", "")
                if repo_html_url and not _is_fp_repo(repo_html_url):
                    repo_urls.add(repo_html_url)
                elif repo_html_url:
                    fp_filtered += 1
                    logger.debug("[gitleaks] FP репозиторий пропущен: %s", repo_html_url)

        except Exception as exc:
            logger.warning("Ошибка поиска репозиториев для '%s': %s", query, exc)

        # Пауза чтобы не попасть в rate limit GitHub Search
        time.sleep(7.0)

    return repo_urls, fp_filtered


# ─── Celery-задача ────────────────────────────────────────────────────────────

def _make_scan_task():
    """
    Регистрирует Celery-задачу только когда Celery доступен.
    В тестовом окружении возвращает заглушку.
    """
    if not _CELERY_AVAILABLE or _celery_app is None:
        return None

    @_celery_app.task(
        bind=True,
        max_retries=2,
        default_retry_delay=60,
        name="workers.tasks.gitleaks.scan_repo",
    )
    def _scan_repo(self, repo_url: str, root_domain: str) -> dict[str, Any]:
        """
        Celery-задача: клонирует репозиторий и сканирует через gitleaks.
        Секреты маскируются ПЕРЕД отправкой в Core API.
        """
        logger.info("Celery задача gitleaks.scan_repo: %s", repo_url)

        try:
            result = scan_github_repo(
                repo_url=repo_url,
                domain=root_domain,
                core_api_url=_worker_settings.CORE_API_URL,
                internal_secret=_worker_settings.INTERNAL_API_SECRET,
            )
        except Exception as exc:
            logger.error("Необработанная ошибка gitleaks для %s: %s", repo_url, exc)
            raise self.retry(exc=exc)

        return result

    return _scan_repo


# Регистрируем Celery-задачу при загрузке модуля (в production окружении)
scan_repo = _make_scan_task()


# ROUTER: api_router.include_router(scheduled_scan.router)
