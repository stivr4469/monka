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

Пароли МАСКИРУЮТСЯ в воркере до отправки в Core API.
В БД попадает только маска — никогда не сырой пароль.
"""
import io
import logging
import re
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Маскирование
# ──────────────────────────────────────────────

def mask_password(pwd: str) -> str:
    """sec****23 — показываем первые 3 и последние 2 символа."""
    if not pwd:
        return "***"
    if len(pwd) <= 5:
        return "*" * len(pwd)
    return pwd[:3] + "*" * (len(pwd) - 5) + pwd[-2:]


# ──────────────────────────────────────────────
# Парсеры форматов
# ──────────────────────────────────────────────

def _parse_block_format(text: str) -> list[dict]:
    """Парсит блочный формат URL/Login/Password."""
    records = []
    url = login = password = ""

    for line in text.splitlines():
        line = line.strip()
        low = line.lower()

        if low.startswith("url:"):
            url = line[4:].strip()
        elif low.startswith("login:") or low.startswith("username:") or low.startswith("user:"):
            login = re.split(r":", line, maxsplit=1)[1].strip()
        elif low.startswith("password:") or low.startswith("pass:"):
            password = re.split(r":", line, maxsplit=1)[1].strip()

        # Сброс блока при пустой строке или разделителе
        if line in ("", "---", "===", "***") and url and login and password:
            records.append({"url": url, "login": login, "password": password})
            url = login = password = ""

    # Последний блок без разделителя
    if url and login and password:
        records.append({"url": url, "login": login, "password": password})

    return records


def _parse_combo_format(text: str) -> list[dict]:
    """Парсит combo-list: login:password или email:password."""
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Пропускаем строки похожие на URL (http://...)
        if line.lower().startswith("http"):
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            login, password = parts[0].strip(), parts[1].strip()
            if login and password:
                records.append({"url": "", "login": login, "password": password})
    return records


def _parse_three_field(text: str) -> list[dict]:
    """Парсит формат url:login:password."""
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":", 2)
        if len(parts) == 3:
            url, login, password = parts
            if login and password:
                # Восстанавливаем https: если URL начинался с http
                if url in ("http", "https"):
                    url = url + ":" + login
                    parts2 = password.split(":", 1)
                    if len(parts2) == 2:
                        login, password = parts2
                records.append({"url": url, "login": login, "password": password})
    return records


def _detect_and_parse(text: str) -> list[dict]:
    """Автоопределение формата и парсинг."""
    # Блочный формат — есть строки начинающиеся с "URL:" / "Login:" / "Password:"
    if re.search(r"^(url|login|username|password|pass):", text, re.IGNORECASE | re.MULTILINE):
        records = _parse_block_format(text)
        if records:
            return records

    # Трёхпольный — большинство строк содержат 2+ двоеточия и начинаются с http
    http_colon_lines = [l for l in text.splitlines() if l.strip().lower().startswith("http")]
    if len(http_colon_lines) > len(text.splitlines()) * 0.3:
        records = _parse_three_field(text)
        if records:
            return records

    # Combo-list — fallback
    return _parse_combo_format(text)


# ──────────────────────────────────────────────
# Сопоставление с доменом
# ──────────────────────────────────────────────

def _extract_domain(url: str, login: str) -> str | None:
    """Извлекает домен из URL или email-логина."""
    if url:
        try:
            parsed = urlparse(url if "://" in url else "https://" + url)
            host = parsed.hostname or ""
            # Убираем www.
            return host.lstrip("www.") if host else None
        except Exception:
            pass
    if "@" in login:
        return login.split("@")[-1].lower()
    return None


def _matches_target(record: dict, target_domain: str) -> bool:
    """Проверяет принадлежит ли запись мониторимому домену (или его поддоменам)."""
    domain = _extract_domain(record.get("url", ""), record.get("login", ""))
    if not domain:
        return False
    return domain == target_domain or domain.endswith("." + target_domain)


# ──────────────────────────────────────────────
# Основная задача
# ──────────────────────────────────────────────

def parse_stealer_log(
    file_bytes: bytes,
    filename: str,
    target_domains: list[str],
    core_api_url: str,
    internal_secret: str,
) -> dict:
    """
    Парсит стилер-лог (ZIP или TXT), сопоставляет с доменами,
    маскирует пароли и отправляет события в Core API.

    Возвращает: {"parsed": N, "matched": M, "sent": K, "errors": E}
    """
    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    headers = {"Authorization": f"Bearer {internal_secret}"}

    texts: list[tuple[str, str]] = []  # (filename, text)

    # Распаковываем ZIP или читаем TXT
    if filename.lower().endswith(".zip") or file_bytes[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                for name in zf.namelist():
                    if name.lower().endswith((".txt", ".log", ".csv")):
                        try:
                            raw = zf.read(name)
                            texts.append((name, raw.decode("utf-8", errors="replace")))
                        except Exception as exc:
                            logger.warning("Не удалось прочитать %s: %s", name, exc)
        except zipfile.BadZipFile as exc:
            logger.error("Повреждённый ZIP: %s", exc)
            return {"parsed": 0, "matched": 0, "sent": 0, "errors": 1}
    else:
        texts.append((filename, file_bytes.decode("utf-8", errors="replace")))

    total_parsed = matched = sent = errors = 0

    for src_filename, text in texts:
        records = _detect_and_parse(text)
        total_parsed += len(records)
        logger.info("[stealer] %s: найдено %d записей", src_filename, len(records))

        for rec in records:
            for domain in target_domains:
                if not _matches_target(rec, domain):
                    continue

                matched += 1
                masked = mask_password(rec.get("password", ""))

                event = {
                    "event_type": "stealer_log",
                    "severity": "critical",
                    "source_type": "stealer_log",
                    "source_name": "stealer-parser",
                    "target_domain": domain,
                    "payload": {
                        "url": rec.get("url", ""),
                        "login": rec.get("login", ""),
                        "password_masked": masked,  # НИКОГДА не сырой пароль
                        "source_file": src_filename,
                    },
                }

                try:
                    r = httpx.post(ingest_url, json=event, headers=headers, timeout=10)
                    status = r.json().get("status", "error")
                    if status in ("accepted", "duplicate"):
                        sent += 1
                    else:
                        errors += 1
                except Exception as exc:
                    logger.error("ingest error: %s", exc)
                    errors += 1

    logger.info(
        "[stealer] Итого: parsed=%d matched=%d sent=%d errors=%d",
        total_parsed, matched, sent, errors,
    )
    return {"parsed": total_parsed, "matched": matched, "sent": sent, "errors": errors}
