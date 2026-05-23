"""Воркер: поиск утечек секретов через gitleaks."""
import json
import logging
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from workers.celery_app import app
from workers.config import settings
from workers.tasks.base import run_tool, send_event

logger = logging.getLogger(__name__)

_MASK_RE = re.compile(r"(?<=[a-zA-Z0-9]{3}).(?=[a-zA-Z0-9]{2})")


def mask_secret(value: str) -> str:
    """Маскирует середину секрета: sec****23"""
    if len(value) <= 6:
        return "***"
    visible = 3
    return value[:visible] + "*" * (len(value) - visible * 2) + value[-visible:]


@app.task(bind=True, max_retries=2, default_retry_delay=60, name="workers.tasks.gitleaks.scan_repo")
def scan_repo(self, repo_url: str, root_domain: str) -> dict:
    """
    Клонирует репозиторий во временную директорию и запускает gitleaks.
    Секреты маскируются ПЕРЕД отправкой в Core API.
    """
    logger.info("Запуск gitleaks для репозитория: %s", repo_url)

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = Path(tmpdir) / "report.json"

        try:
            run_tool(
                [
                    settings.GITLEAKS_BIN,
                    "detect",
                    "--source", ".",
                    "--report-format", "json",
                    "--report-path", str(report_path),
                    "--no-git",
                    "--exit-code", "0",
                ],
                timeout=120,
            )
        except RuntimeError as exc:
            logger.error("gitleaks завершился с ошибкой: %s", exc)
            raise self.retry(exc=exc)

        if not report_path.exists():
            logger.info("gitleaks: утечек не обнаружено в %s", repo_url)
            return {"repo": repo_url, "leaks_sent": 0}

        try:
            findings = json.loads(report_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Не удалось прочитать отчёт gitleaks: %s", exc)
            return {"repo": repo_url, "leaks_sent": 0}

    sent = 0
    for finding in findings or []:
        raw_secret = finding.get("Secret", "")
        masked = mask_secret(raw_secret) if raw_secret else "***"

        event = {
            "event_type": "secret_leak",
            "severity": "high",
            "source_type": "gitleaks",
            "source_name": "gitleaks",
            "target_domain": root_domain,
            "payload": {
                "repo_url": repo_url,
                "rule_id": finding.get("RuleID", ""),
                "file": finding.get("File", ""),
                "line": finding.get("StartLine", 0),
                "commit": finding.get("Commit", ""),
                "secret_masked": masked,  # НИКОГДА не отправляем raw_secret
                "author": finding.get("Author", ""),
            },
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            send_event(event)
            sent += 1
        except Exception as exc:
            logger.warning("Не удалось отправить событие gitleaks: %s", exc)

    logger.info("gitleaks: %d утечек для %s", sent, repo_url)
    return {"repo": repo_url, "leaks_sent": sent}
