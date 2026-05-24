"""
Воркер: Human OSINT — профилирование сотрудников компании (задача 9.D).

Источники данных (все публичные, без авторизации):
- GitHub API: поиск пользователей с email @domain.com
  (rate limit 10 req/min без токена, 30 req/min с GITHUB_TOKEN)
- DuckDuckGo Lite: поиск site:linkedin.com/in "company" без авторизации

Важно:
  НЕ использовать selenium/playwright — только httpx.
  НЕ парсить закрытые разделы LinkedIn (нарушение ToS).
  Используем только публичный поиск DDG + GitHub Search API.
  Email из результатов НЕ хранятся — только шаблоны-паттерны.
"""
from __future__ import annotations

import html
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Конфигурация
# ──────────────────────────────────────────────

_GITHUB_SEARCH_URL = "https://api.github.com/search/users"
_DDG_SEARCH_URL = "https://lite.duckduckgo.com/lite/"
_REQUEST_TIMEOUT = 15
_DDG_RATE_SLEEP = 2.0   # секунды между запросами к DDG
_GITHUB_RATE_SLEEP = 2.0  # секунды между запросами к GitHub API

# Минимальная длина заголовка результата DDG, чтобы не принимать мусор
_DDG_TITLE_MIN_LEN = 3
_DDG_TITLE_MAX_LEN = 200
_DDG_MAX_RESULTS = 20

# Должности с повышенным риском фишинга
_VIP_TITLES: frozenset[str] = frozenset({
    "ceo", "chief executive", "founder", "co-founder",
    "cto", "chief technology", "vp engineering", "head of engineering",
    "ciso", "chief information security", "security officer",
    "devops", "sre", "site reliability", "infrastructure",
    "sysadmin", "system administrator", "network admin",
    "database admin", "dba", "backend developer", "backend engineer",
})

# Разделители имя-должность в заголовках LinkedIn
_LINKEDIN_SEPS = (" - ", " | ", " — ", " · ")

# Паттерн для очистки не-ASCII при генерации email
_NON_ALPHA_RE = re.compile(r"[^a-z]")

# Паттерн для извлечения LinkedIn-ссылок из HTML DuckDuckGo Lite
_DDG_LINKEDIN_RE = re.compile(
    r'<a[^>]+href="(https?://(?:www\.)?linkedin\.com/in/[^"]+)"[^>]*>([^<]+)</a>',
    re.IGNORECASE,
)


# ──────────────────────────────────────────────
# Внутренние данные-объекты
# ──────────────────────────────────────────────

@dataclass
class GitHubProfile:
    login: str
    html_url: str
    name: str | None = None


@dataclass
class LinkedInProfile:
    url: str
    raw_title: str
    name: str | None = None
    job_title: str | None = None
    is_vip: bool = False
    email_patterns: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────
# Генерация email-паттернов
# ──────────────────────────────────────────────

def _generate_email_patterns(first: str, last: str, domain: str) -> list[str]:
    """
    Генерирует вероятные корпоративные email-адреса по имени и фамилии.

    Эти шаблоны — инструмент оценки риска фишинга, не хранятся отдельно.
    Сортировка: наиболее распространённые паттерны первыми.
    """
    f = _NON_ALPHA_RE.sub("", first.lower().strip())
    l = _NON_ALPHA_RE.sub("", last.lower().strip())
    if not f or not l:
        return []

    return [
        f"{f}.{l}@{domain}",    # john.doe@company.com  — наиболее распространённый
        f"{f[0]}{l}@{domain}",  # jdoe@company.com
        f"{f[0]}.{l}@{domain}", # j.doe@company.com
        f"{f}{l}@{domain}",     # johndoe@company.com
        f"{f}@{domain}",        # john@company.com
        f"{l}.{f}@{domain}",    # doe.john@company.com
    ]


# ──────────────────────────────────────────────
# GitHub Search
# ──────────────────────────────────────────────

def _build_github_headers(github_token: str | None) -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    return headers


def _search_github_users(
    domain: str,
    github_token: str | None = None,
) -> list[GitHubProfile]:
    """
    Ищет GitHub-пользователей по email-домену компании.

    GitHub Search API: GET /search/users?q={domain}+in:email
    Rate limit без токена: 10 req/min — отправляем максимум 2 запроса.
    С GITHUB_TOKEN: 30 req/min.
    """
    headers = _build_github_headers(github_token)
    queries = [
        f"{domain} in:email",
        f"@{domain} in:email",
    ]

    profiles: dict[str, GitHubProfile] = {}  # дедупликация по login

    for query in queries:
        try:
            with httpx.Client(timeout=_REQUEST_TIMEOUT, headers=headers) as client:
                resp = client.get(
                    _GITHUB_SEARCH_URL,
                    params={"q": query, "per_page": 30},
                )

            if resp.status_code == 403:
                logger.warning(
                    "[human_osint][github] Rate limit exceeded для домена %s. "
                    "Установите GITHUB_TOKEN для увеличения лимита.",
                    domain,
                )
                break
            if resp.status_code == 422:
                logger.debug("[human_osint][github] Невалидный запрос: %s", query)
                continue
            if resp.status_code != 200:
                logger.debug(
                    "[human_osint][github] HTTP %d для запроса: %s",
                    resp.status_code, query,
                )
                continue

            data = resp.json()
            for item in data.get("items", []):
                login = item.get("login", "")
                if login and login not in profiles:
                    profiles[login] = GitHubProfile(
                        login=login,
                        html_url=item.get("html_url", f"https://github.com/{login}"),
                        name=item.get("name"),
                    )

            time.sleep(_GITHUB_RATE_SLEEP)

        except httpx.TimeoutException:
            logger.debug("[human_osint][github] Timeout для запроса: %s", query)
        except Exception as exc:
            logger.debug("[human_osint][github] Ошибка поиска: %s", exc)

    return list(profiles.values())


# ──────────────────────────────────────────────
# DuckDuckGo LinkedIn Search
# ──────────────────────────────────────────────

def _search_ddg_linkedin(domain: str, company_name: str) -> list[dict[str, str]]:
    """
    Поиск LinkedIn профилей через DuckDuckGo Lite (публичный, без авторизации).

    Запрос: site:linkedin.com/in "{company_name}"
    Парсим только заголовки и URL из HTML ответа DDG Lite — на LinkedIn не ходим.

    Возвращает список {"url": ..., "title": ...}
    """
    query = f'site:linkedin.com/in "{company_name}"'
    results: list[dict[str, str]] = []

    try:
        with httpx.Client(
            timeout=_REQUEST_TIMEOUT,
            follow_redirects=True,
        ) as client:
            resp = client.post(
                _DDG_SEARCH_URL,
                data={"q": query, "kl": "en-us"},
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) "
                        "Gecko/20100101 Firefox/120.0"
                    ),
                    "Accept": "text/html,application/xhtml+xml",
                    "Accept-Language": "en-US,en;q=0.9",
                },
            )

        if resp.status_code != 200:
            logger.debug(
                "[human_osint][ddg] HTTP %d для запроса company=%s",
                resp.status_code, company_name,
            )
            return []

        text = html.unescape(resp.text)

        for match in _DDG_LINKEDIN_RE.finditer(text):
            url = match.group(1).strip()
            title = match.group(2).strip()

            if _DDG_TITLE_MIN_LEN <= len(title) <= _DDG_TITLE_MAX_LEN:
                results.append({"url": url, "title": title})

            if len(results) >= _DDG_MAX_RESULTS:
                break

        time.sleep(_DDG_RATE_SLEEP)

    except httpx.TimeoutException:
        logger.debug("[human_osint][ddg] Timeout для company=%s", company_name)
    except Exception as exc:
        logger.debug("[human_osint][ddg] Ошибка поиска: %s", exc)

    return results


# ──────────────────────────────────────────────
# Парсинг заголовков LinkedIn
# ──────────────────────────────────────────────

def _parse_linkedin_title(title: str) -> tuple[str | None, str | None, bool]:
    """
    Парсит заголовок LinkedIn профиля из поиска DDG.

    Примеры заголовков:
      "John Doe - Senior DevOps Engineer at TechCorp"
      "Jane Smith | CTO at StartupXYZ"
      "Alex Johnson — Backend Developer · Company"

    Возвращает: (name, job_title, is_vip)
    """
    name: str | None = None
    job_title: str | None = None

    for sep in _LINKEDIN_SEPS:
        if sep in title:
            parts = title.split(sep, 1)
            name = parts[0].strip() or None
            job_title = parts[1].strip() if len(parts) > 1 else None
            break

    if not name:
        # Заголовок без разделителя — берём как имя (обрезаем до 50 символов)
        name = title[:50].strip() or None

    is_vip = any(vip in (job_title or "").lower() for vip in _VIP_TITLES)

    return name, job_title, is_vip


def _split_name(name: str) -> tuple[str, str] | None:
    """
    Разбивает полное имя на (first, last).
    Возвращает None если имя не состоит из ровно двух слов.
    """
    parts = name.strip().split()
    if len(parts) == 2:  # noqa: PLR2004
        return parts[0], parts[1]
    return None


# ──────────────────────────────────────────────
# Формирование событий
# ──────────────────────────────────────────────

def _github_event(domain: str, profile: GitHubProfile) -> dict[str, Any]:
    return {
        "event_type": "human_intel",
        "severity": "info",
        "source_type": "osint",
        "source_name": "github_osint",
        "target_domain": domain,
        "payload": {
            "github_login": profile.login,
            "profile_url": profile.html_url,
            "name": profile.name,
            "source": "github",
        },
    }


def _linkedin_event(domain: str, profile: LinkedInProfile) -> dict[str, Any]:
    severity = "medium" if profile.is_vip else "low"
    return {
        "event_type": "human_intel",
        "severity": severity,
        "source_type": "osint",
        "source_name": "linkedin_osint",
        "target_domain": domain,
        "payload": {
            "name": profile.name,
            "job_title": profile.job_title,
            "is_vip": profile.is_vip,
            "linkedin_url": profile.url,
            # Только паттерны — не реальные адреса
            "email_patterns": profile.email_patterns,
            "source": "linkedin_ddg",
        },
    }


# ──────────────────────────────────────────────
# Главная функция
# ──────────────────────────────────────────────

def run_human_osint(
    domain: str,
    core_api_url: str,
    internal_secret: str,
    github_token: str | None = None,
) -> dict[str, Any]:
    """
    Запускает Human OSINT для домена: GitHub + LinkedIn (через DDG).

    Возвращает сводку:
      {
        "domain": str,
        "github_profiles": int,
        "linkedin_profiles": int,
        "vip_found": int,
        "email_patterns_generated": int,
        "sent": int,
        "errors": int,
      }
    """
    domain = domain.strip().lower()
    # Имя компании — первая часть домена без TLD, с заглавной
    company_name = domain.split(".")[0].capitalize()

    logger.info(
        "[human_osint] Старт: domain=%s company=%s",
        domain, company_name,
    )

    # ── 1. GitHub Search ──────────────────────────────────────────────────────
    github_profiles = _search_github_users(domain, github_token)
    logger.info("[human_osint] GitHub: найдено %d профилей", len(github_profiles))

    # ── 2. DDG LinkedIn Search ────────────────────────────────────────────────
    raw_linkedin = _search_ddg_linkedin(domain, company_name)
    logger.info("[human_osint] DDG: найдено %d LinkedIn заголовков", len(raw_linkedin))

    # ── 3. Парсинг LinkedIn профилей ──────────────────────────────────────────
    linkedin_profiles: list[LinkedInProfile] = []
    for item in raw_linkedin:
        name, job_title, is_vip = _parse_linkedin_title(item["title"])
        if not name:
            continue

        patterns: list[str] = []
        name_parts = _split_name(name)
        if name_parts:
            patterns = _generate_email_patterns(name_parts[0], name_parts[1], domain)

        linkedin_profiles.append(LinkedInProfile(
            url=item["url"],
            raw_title=item["title"],
            name=name,
            job_title=job_title,
            is_vip=is_vip,
            email_patterns=patterns,
        ))

    vip_count = sum(1 for p in linkedin_profiles if p.is_vip)
    total_patterns = sum(len(p.email_patterns) for p in linkedin_profiles)

    logger.info(
        "[human_osint] LinkedIn: профилей=%d VIP=%d email_patterns=%d",
        len(linkedin_profiles), vip_count, total_patterns,
    )

    # ── 4. Сборка событий ─────────────────────────────────────────────────────
    events: list[dict[str, Any]] = []

    for profile in github_profiles:
        events.append(_github_event(domain, profile))

    for profile in linkedin_profiles:
        events.append(_linkedin_event(domain, profile))

    # ── 5. Отправка в Core API ────────────────────────────────────────────────
    sent = errors = 0
    if events:
        result = bulk_ingest(events, core_api_url, internal_secret)
        sent = result["sent"]
        errors = result["errors"]

    logger.info(
        "[human_osint] Итого domain=%s github=%d linkedin=%d vip=%d patterns=%d sent=%d errors=%d",
        domain, len(github_profiles), len(linkedin_profiles),
        vip_count, total_patterns, sent, errors,
    )

    return {
        "domain": domain,
        "github_profiles": len(github_profiles),
        "linkedin_profiles": len(linkedin_profiles),
        "vip_found": vip_count,
        "email_patterns_generated": total_patterns,
        "sent": sent,
        "errors": errors,
    }
