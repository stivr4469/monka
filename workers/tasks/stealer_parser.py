"""
Парсер стилер-логов.

Поддерживаемые форматы:
  1. Блочный (типичный для Redline/Vidar/Raccoon):
       URL: https://mail.example.com
       Login: user@example.com
       Password: secret123

  2. Комбо-лист (email:password или login:password):
       user@example.com:secret123

  3. Трёхпольный (url:login:password):
       https://example.com:user@example.com:secret123

7.A: Стриминговый парсинг — принимает Path на диск вместо bytes в RAM.
7.B: Батчевая отправка через bulk_ingest вместо N×HTTP.
"""
import io
import logging
import os
import re
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from crypto import encrypt_password
from workers.tasks.bulk_ingest import bulk_ingest
from workers.tasks.cookie_validator import validate_cookies_from_zip

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Парсеры форматов
# ──────────────────────────────────────────────

def _parse_block_format(lines: list[str]) -> list[dict]:
    """Парсит блочный формат URL/Login/Password."""
    records = []
    url = login = password = ""

    for line in lines:
        line = line.strip()
        low = line.lower()

        if low.startswith("url:"):
            url = line[4:].strip()
        elif low.startswith("login:") or low.startswith("username:") or low.startswith("user:"):
            login = re.split(r":", line, maxsplit=1)[1].strip()
        elif low.startswith("password:") or low.startswith("pass:"):
            password = re.split(r":", line, maxsplit=1)[1].strip()

        if line in ("", "---", "===", "***") and url and login and password:
            records.append({"url": url, "login": login, "password": password})
            url = login = password = ""

    if url and login and password:
        records.append({"url": url, "login": login, "password": password})

    return records


def _parse_combo_format(lines: list[str]) -> list[dict]:
    """Парсит combo-list: login:password или email:password."""
    records = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.lower().startswith("http"):
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            login, password = parts[0].strip(), parts[1].strip()
            if login and password:
                records.append({"url": "", "login": login, "password": password})
    return records


def _parse_three_field(lines: list[str]) -> list[dict]:
    """Парсит формат url:login:password."""
    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(":", 2)
        if len(parts) == 3:
            url, login, password = parts
            if login and password:
                if url in ("http", "https"):
                    url = url + ":" + login
                    parts2 = password.split(":", 1)
                    if len(parts2) == 2:
                        login, password = parts2
                records.append({"url": url, "login": login, "password": password})
    return records


def _detect_and_parse(lines: list[str]) -> list[dict]:
    """Автоопределение формата и парсинг."""
    text_sample = "\n".join(lines[:200])

    if re.search(r"^(url|login|username|password|pass):", text_sample, re.IGNORECASE | re.MULTILINE):
        records = _parse_block_format(lines)
        if records:
            return records

    http_lines = sum(1 for l in lines if l.strip().lower().startswith("http"))
    if http_lines > len(lines) * 0.3:
        records = _parse_three_field(lines)
        if records:
            return records

    return _parse_combo_format(lines)


# ──────────────────────────────────────────────
# Сопоставление с доменом
# ──────────────────────────────────────────────

def _extract_domain(url: str, login: str) -> str | None:
    """Извлекает домен из URL или email-логина."""
    if url:
        try:
            parsed = urlparse(url if "://" in url else "https://" + url)
            host = parsed.hostname or ""
            return host.lstrip("www.") if host else None
        except Exception:
            pass
    if "@" in login:
        return login.split("@")[-1].lower()
    return None


def _matches_target(record: dict, target_domain: str) -> bool:
    """Проверяет принадлежность записи мониторимому домену (включая поддомены)."""
    domain = _extract_domain(record.get("url", ""), record.get("login", ""))
    if not domain:
        return False
    return domain == target_domain or domain.endswith("." + target_domain)


# ──────────────────────────────────────────────
# 7.A: Стриминговый итератор строк из ZIP без загрузки в RAM
# ──────────────────────────────────────────────

def _iter_text_files_from_zip(file_path: Path):
    """
    Генератор: (filename, lines) для каждого .txt/.log/.csv внутри ZIP.
    Читает построчно через TextIOWrapper — не буферизует файл в RAM.
    """
    with zipfile.ZipFile(file_path) as zf:
        for member in zf.namelist():
            if not member.lower().endswith((".txt", ".log", ".csv")):
                continue
            try:
                with zf.open(member) as raw_file:
                    text_file = io.TextIOWrapper(raw_file, encoding="utf-8", errors="replace")
                    lines = list(text_file)  # читаем построчно
                yield member, lines
            except Exception as exc:
                logger.warning("[stealer] Не удалось прочитать %s: %s", member, exc)


# ──────────────────────────────────────────────
# Основная задача
# ──────────────────────────────────────────────

def parse_stealer_log(
    file_path: Path,
    filename: str,
    target_domains: list[str],
    core_api_url: str,
    internal_secret: str,
) -> dict:
    """
    Парсит стилер-лог (ZIP или TXT) по пути на диске.
    Отправляет события в Core API через bulk_ingest.
    Удаляет временный файл после обработки.

    Возвращает: {"parsed": N, "matched": M, "sent": K, "errors": E}
    """
    total_parsed = matched = 0
    events_batch: list[dict] = []

    try:
        # Определяем формат по имени файла и сигнатуре
        is_zip = filename.lower().endswith(".zip") or (
            file_path.stat().st_size >= 2 and file_path.read_bytes()[:2] == b"PK"
        )

        if is_zip:
            file_pairs = list(_iter_text_files_from_zip(file_path))
        else:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            file_pairs = [(filename, lines)]

        for src_filename, lines in file_pairs:
            records = _detect_and_parse(lines)
            total_parsed += len(records)
            logger.info("[stealer] %s: найдено %d записей", src_filename, len(records))

            for rec in records:
                for domain in target_domains:
                    if not _matches_target(rec, domain):
                        continue

                    matched += 1
                    raw_pwd = rec.get("password", "")
                    enc_pwd = encrypt_password(raw_pwd, internal_secret)

                    events_batch.append({
                        "event_type": "stealer_log",
                        "severity": "critical",
                        "source_type": "stealer_log",
                        "source_name": "stealer-parser",
                        "target_domain": domain,
                        "payload": {
                            "url": rec.get("url", ""),
                            "login": rec.get("login", ""),
                            "password_enc": enc_pwd,
                            "source_file": src_filename,
                        },
                    })

        # 7.B: отправляем батчем
        result = bulk_ingest(events_batch, core_api_url, internal_secret)
        sent = result["sent"]
        errors = result["errors"]

        # 9.C: проверка активности сессионных кук (только для ZIP-архивов стилеров)
        if is_zip and target_domains:
            try:
                # Используем первый домен как основной для фильтрации
                primary_domain = target_domains[0]
                cookie_result = validate_cookies_from_zip(
                    file_path, primary_domain, core_api_url, internal_secret
                )
                logger.info("[stealer] Куки проверены: %s", cookie_result)
            except Exception as exc:
                logger.warning("[stealer] Ошибка валидации куков: %s", exc)

    except Exception as exc:
        logger.error("[stealer] Критическая ошибка парсинга: %s", exc)
        sent = 0
        errors = 1
    finally:
        # 7.A.4: удаляем временный файл после обработки
        try:
            file_path.unlink(missing_ok=True)
        except Exception as exc:
            logger.warning("[stealer] Не удалось удалить временный файл %s: %s", file_path, exc)

    logger.info(
        "[stealer] Итого: parsed=%d matched=%d sent=%d errors=%d",
        total_parsed, matched, sent, errors,
    )
    return {"parsed": total_parsed, "matched": matched, "sent": sent, "errors": errors}
