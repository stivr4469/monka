"""
DumpsterDiver — анализ энтропии строк в файлах для поиска ключей и токенов.

Анализирует PDF, DOCX, JS, XML, конфиги на предмет строк с высокой энтропией.
Высокая энтропия = вероятный приватный ключ, пароль или API-токен.

Два режима:
  1. DumpsterDiver CLI (securing/DumpsterDiver) если установлен
  2. Встроенная entropy-эвристика на Python (всегда работает как fallback)

Установка: pip install DumpsterDiver
"""
from __future__ import annotations

import logging
import math
import os
import re
import shutil
import string
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from workers.celery_app import app
from workers.config import settings
from workers.tasks.base import IngestClient, run_tool

logger = logging.getLogger(__name__)

_MIN_ENTROPY        = 4.0   # минимальная энтропия Шеннона для флага (0-8)
_MIN_STRING_LEN     = 20    # минимальная длина строки
_MAX_FILE_SIZE_MB   = 50    # максимальный размер файла для анализа
_SUPPORTED_EXTS     = {".js", ".json", ".xml", ".yaml", ".yml", ".env",
                       ".config", ".conf", ".txt", ".py", ".sh", ".php"}

# Шаблоны известных типов секретов для быстрого детекта
_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"(?i)aws.{0,20}(?:key|secret).{0,20}['\"][A-Za-z0-9+/]{20,}['\"]", "AWS Credential"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key"),
    (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "Hardcoded Password"),
    (r"(?i)(?:api_key|apikey|api-key)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "API Key"),
    (r"(?i)(?:token|secret)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "Token/Secret"),
    (r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.", "JWT Token"),
    (r"(?i)mongodb(?:\+srv)?://[^\s'\"]+", "MongoDB Connection String"),
    (r"(?i)postgresql://[^\s'\"]+", "PostgreSQL Connection String"),
]


# ─── Встроенная entropy-эвристика ────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Энтропия Шеннона для строки (0.0 – log2(len(charset)))."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


_BASE64_CHARS = set(string.ascii_letters + string.digits + "+/=")
_HEX_CHARS    = set(string.hexdigits)


def _extract_high_entropy_strings(text: str) -> list[dict[str, Any]]:
    """
    Ищет строки с высокой энтропией — вероятные ключи и токены.
    Фильтрует только строки из base64/hex-алфавита нужной длины.
    """
    findings = []

    # Разбиваем по пробельным символам и кавычкам
    tokens = re.split(r"""[\s'"`,;(){}[\]]+""", text)
    for token in tokens:
        if len(token) < _MIN_STRING_LEN:
            continue
        # Проверяем что строка состоит преимущественно из base64/hex символов
        charset_ratio = sum(1 for c in token if c in _BASE64_CHARS) / len(token)
        if charset_ratio < 0.85:
            continue
        entropy = _shannon_entropy(token)
        if entropy >= _MIN_ENTROPY:
            findings.append({
                "string":  token[:200],   # ограничиваем длину
                "entropy": round(entropy, 2),
                "length":  len(token),
                "type":    "high_entropy_string",
            })

    return findings


def _detect_patterns(text: str) -> list[dict[str, Any]]:
    """Детектирует известные паттерны секретов через regex."""
    findings = []
    for pattern, label in _SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            matched = match.group(0)
            findings.append({
                "string":  matched[:200],
                "entropy": round(_shannon_entropy(matched), 2),
                "length":  len(matched),
                "type":    label,
            })
    return findings


def _analyze_file_content(content: str, filename: str) -> list[dict[str, Any]]:
    """Полный анализ содержимого файла: энтропия + паттерны."""
    findings = _extract_high_entropy_strings(content)
    findings += _detect_patterns(content)
    # Дедупликация по строке
    seen: set[str] = set()
    unique = []
    for f in findings:
        key = f["string"][:50]
        if key not in seen:
            seen.add(key)
            f["filename"] = filename
            unique.append(f)
    return unique


def _secret_event(
    target_domain: str,
    finding: dict[str, Any],
) -> dict[str, Any]:
    entropy = finding.get("entropy", 0)
    severity = "critical" if entropy >= 6.0 else "high" if entropy >= 5.0 else "medium"
    return {
        "event_type":   "secret_in_file",
        "severity":     severity,
        "source_type":  "scanner",
        "source_name":  "dumpster_diver",
        "target_domain": target_domain,
        "payload": {
            "filename":    finding.get("filename", ""),
            "secret_type": finding.get("type", "unknown"),
            "entropy":     finding.get("entropy", 0),
            "preview":     finding.get("string", "")[:80] + "...",
            "detected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
    }


# ─── Celery-задачи ────────────────────────────────────────────────────────────

@app.task(bind=True, name="dumpster_diver.analyze_file", max_retries=1)
def analyze_file(self, file_path: str, target_domain: str) -> dict[str, Any]:
    """
    Анализирует файл на предмет секретов и высокой энтропии.

    Args:
        file_path:     Путь к локальному файлу (JS, PDF, DOCX, конфиг и т.д.)
        target_domain: Домен клиента для группировки событий.
    """
    path = Path(file_path)
    if not path.exists():
        return {"status": "error", "error": f"Файл не найден: {file_path}", "findings": 0}

    size_mb = path.stat().st_size / (1024 * 1024)
    if size_mb > _MAX_FILE_SIZE_MB:
        logger.warning("[dumpster] Файл слишком большой: %.1f MB > %d MB", size_mb, _MAX_FILE_SIZE_MB)
        return {"status": "skipped", "reason": "file_too_large", "findings": 0}

    filename = path.name
    ext = path.suffix.lower()

    # Пробуем DumpsterDiver CLI сначала
    dd_binary = shutil.which("DumpsterDiver") or shutil.which("dumpsterdiver")

    if dd_binary:
        logger.info("[dumpster] Используем DumpsterDiver CLI для %s", filename)
        try:
            stdout, _ = run_tool(
                [dd_binary, "-p", str(path), "--min-entropy", str(_MIN_ENTROPY)],
                timeout=60,
            )
            findings_count = stdout.count("entropy:")
            logger.info("[dumpster] CLI: %d находок в %s", findings_count, filename)
        except RuntimeError as exc:
            logger.warning("[dumpster] CLI ошибка, переключаюсь на Python: %s", exc)
            dd_binary = None

    # Python fallback (или основной режим для текстовых файлов)
    try:
        if ext in _SUPPORTED_EXTS:
            content = path.read_text(encoding="utf-8", errors="ignore")
        else:
            # Для бинарных форматов (PDF, DOCX) — пробуем извлечь текст
            content = path.read_bytes().decode("utf-8", errors="ignore")
    except Exception as exc:
        logger.error("[dumpster] Не удалось прочитать файл %s: %s", filename, exc)
        return {"status": "error", "error": str(exc), "findings": 0}

    findings = _analyze_file_content(content, filename)
    logger.info("[dumpster] Python: %d находок в %s", len(findings), filename)

    if not findings:
        return {"status": "ok", "file": filename, "findings": 0}

    # Отправляем в ingest
    client = IngestClient(
        core_api_url=settings.CORE_API_URL,
        internal_secret=settings.INTERNAL_API_SECRET,
    )
    sent = 0
    critical = sum(1 for f in findings if f.get("entropy", 0) >= 6.0)
    for finding in findings:
        try:
            client.send(_secret_event(target_domain, finding))
            sent += 1
        except Exception as exc:
            logger.warning("[dumpster] Ingest error: %s", exc)

    logger.info(
        "[dumpster] %s: %d находок (%d критических), отправлено %d",
        filename, len(findings), critical, sent,
    )
    return {
        "status":   "ok",
        "file":     filename,
        "findings": len(findings),
        "critical": critical,
        "sent":     sent,
    }


@app.task(bind=True, name="dumpster_diver.analyze_js_files", max_retries=1)
def analyze_js_files(self, js_urls: list[str], target_domain: str) -> dict[str, Any]:
    """
    Скачивает JS-файлы и анализирует их на предмет секретов.
    Используется после katana для анализа найденных скриптов.
    """
    import httpx  # noqa: PLC0415

    total_findings = 0
    total_critical = 0
    analyzed = 0

    for js_url in js_urls[:20]:   # лимит 20 JS-файлов за один запуск
        if not js_url.endswith(".js"):
            continue
        try:
            resp = httpx.get(js_url, timeout=10.0, follow_redirects=True)
            if resp.status_code != 200:
                continue

            # Сохраняем во временный файл для analyze_file
            with tempfile.NamedTemporaryFile(
                suffix=".js", mode="wb", delete=False
            ) as tmp:
                tmp.write(resp.content)
                tmp_path = tmp.name

            try:
                result = analyze_file.run(tmp_path, target_domain)
                total_findings += result.get("findings", 0)
                total_critical += result.get("critical", 0)
                analyzed += 1
            finally:
                Path(tmp_path).unlink(missing_ok=True)

        except Exception as exc:
            logger.warning("[dumpster] Не удалось обработать %s: %s", js_url, exc)

    return {
        "status":          "ok",
        "js_files_analyzed": analyzed,
        "total_findings":  total_findings,
        "total_critical":  total_critical,
    }
