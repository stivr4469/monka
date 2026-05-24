"""
Парсер сайтов утечек ransomware-группировок через Tor.

Известные .onion-адреса групп взяты из публичного репозитория
deepdarkCTI (https://github.com/fastfire/deepdarkCTI) и аналогичных
открытых источников разведки угроз (threat intelligence).

Принципы:
  - Каждый сайт разбирается независимо (try/except)
  - Tor недоступен → сразу возвращаем {"error": ..., "tor_required": True}
  - Поиск домена: нормализация (без www, нижний регистр)
  - shell=False везде, никаких subprocess
  - Таймаут 30с на каждый .onion-запрос
"""
import logging
import re
from typing import Any, Optional

import httpx

from tasks.tor_client import check_tor_available, get_tor_client

logger = logging.getLogger(__name__)

# Таймаут HTTP-запросов к .onion-сайтам
_TOR_TIMEOUT = 30.0

# Максимальная длина snippet (согласно общей спецификации воркеров)
_SNIPPET_MAX_LEN = 500

# Паттерн для очистки HTML-тегов
_HTML_TAG_RE = re.compile(r"<[^>]+>")


# ──────────────────────────────────────────────
# Известные .onion-адреса ransomware-группировок
# ──────────────────────────────────────────────
# Источники: deepdarkCTI, ransomwatch.telemetry.ltd, публичные отчёты
# Адреса актуальны на момент написания, но группы часто меняют адреса.
# При недоступности адреса — ошибка логируется, остальные группы проверяются.

ONION_SITES: dict[str, str] = {
    # LockBit — одна из крупнейших RaaS-группировок
    "lockbit": "lockbit3753plprasmtxxe5o7ljm5msxzrwejuq4l5xbx6xgzqtwboad.onion",

    # ALPHV / BlackCat — Rust-based RaaS
    "alphv": "alphvmmm3vkrm2b7pqjqrp5jrqezhq5nm7etv3d4czxzv6ziqtaizpad.onion",

    # Play (PlayCrypt) — группа без RaaS-модели
    "play": "k7kg3jqxang3wh7262376get6u34dqxovguvnyg742dfprtmzq3aonyd.onion",

    # Clop — специализируется на MOVEit, GoAnywhere
    "clop": "santat7kplnzbbwltnkphutyiys5qi7x3go4lgdp755ikvqos3nfscyd.onion",

    # RansomHub — новая группа 2024 года, очень активная
    "ransomhub": "ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion",

    # Akira — активна с 2023, атакует VMware ESXi
    "akira": "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion",

    # NoEscape — группа 2023 года, атакует healthcare
    "noescape": "noescape7nducd63ikn2ldxf7an3y5yqfwnc2ofkf6djlzpxf3rpd5yd.onion",

    # Hunters International — наследник Hive
    "hunters": "hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejkid.onion",
}

# Паттерн для нормализации домена: убираем www. и protocol
_WWW_RE = re.compile(r"^(https?://)?(www\.)?", re.IGNORECASE)


def _normalize_domain(domain: str) -> str:
    """Приводит домен к виду без www и протокола, в нижнем регистре."""
    return _WWW_RE.sub("", domain.strip()).lower().rstrip("/")


def _strip_html(text: str) -> str:
    """Убирает HTML-теги из текста."""
    return _HTML_TAG_RE.sub(" ", text).strip()


def _truncate(text: str) -> str:
    """Обрезает текст до _SNIPPET_MAX_LEN символов."""
    return text[:_SNIPPET_MAX_LEN]


def _extract_domain_variants(domain: str) -> list[str]:
    """
    Возвращает варианты домена для поиска.

    Например, для "example.com":
      ["example.com", "www.example.com", "example"]
    Это снижает количество пропусков при размытом написании на сайтах.
    """
    clean = _normalize_domain(domain)
    root = clean.split(".")[0]  # пример: "example" из "example.com"
    return list(dict.fromkeys([clean, f"www.{clean}", root]))  # без дублей


def _domain_mentioned(text: str, variants: list[str]) -> bool:
    """Возвращает True если хотя бы один вариант домена встречается в тексте."""
    text_lower = text.lower()
    return any(v in text_lower for v in variants)


# ──────────────────────────────────────────────
# Парсинг одного сайта
# ──────────────────────────────────────────────

def parse_ransomware_site(
    group_name: str,
    onion_url: str,
    tor_client: httpx.Client,
) -> list[dict[str, Any]]:
    """
    Скачивает страницу .onion-сайта группы и возвращает список жертв.

    Поиск жертв ведётся эвристически — HTML-структура у каждой группы своя,
    поэтому ищем ключевые паттерны: блоки с именами жертв, доменами, датами.

    Аргументы:
        group_name  — строковый идентификатор группы (например, "lockbit")
        onion_url   — .onion-адрес без схемы (схема добавляется автоматически)
        tor_client  — уже созданный httpx.Client с Tor-прокси

    Возвращает:
        list[dict] — каждый dict: {victim, domain, published_at, group}
        [] при любой ошибке (логируется)
    """
    full_url = f"http://{onion_url}" if not onion_url.startswith("http") else onion_url
    results: list[dict[str, Any]] = []

    try:
        logger.info("[ransomware_sites][%s] Запрашиваем %s", group_name, full_url)
        response = tor_client.get(full_url, timeout=_TOR_TIMEOUT)

        if response.status_code != 200:
            logger.warning(
                "[ransomware_sites][%s] HTTP %d от %s",
                group_name,
                response.status_code,
                onion_url,
            )
            return []

        html = response.text

        # Извлекаем структурированные данные из HTML
        # Многие ransomware-сайты используют похожие паттерны: карточки жертв
        # с классами типа "victim", "company", "post", "target"
        results = _parse_victims_from_html(html, group_name)
        logger.info(
            "[ransomware_sites][%s] Найдено %d жертв на %s",
            group_name,
            len(results),
            onion_url,
        )

    except httpx.TimeoutException:
        logger.warning("[ransomware_sites][%s] Таймаут запроса к %s", group_name, onion_url)
    except httpx.ConnectError as exc:
        logger.warning("[ransomware_sites][%s] Ошибка подключения к %s: %s", group_name, onion_url, exc)
    except Exception as exc:
        logger.warning("[ransomware_sites][%s] Неожиданная ошибка: %s", group_name, exc)

    return results


def _parse_victims_from_html(html: str, group_name: str) -> list[dict[str, Any]]:
    """
    Эвристический парсер HTML страниц ransomware-сайтов.

    Ищет паттерны, типичные для большинства leak-сайтов:
    - Элементы с классами: victim, company, target, post, entry
    - Ссылки вида /victim/<name>, /post/<id>
    - Текстовые блоки с датой публикации
    """
    results: list[dict[str, Any]] = []

    # Паттерн 1: карточки жертв с атрибутом class, содержащим "victim"|"company"|"target"
    card_re = re.compile(
        r'<(?:div|li|article|section)[^>]+class="[^"]*(?:victim|company|target|post|entry)[^"]*"[^>]*>(.*?)</(?:div|li|article|section)>',
        re.IGNORECASE | re.DOTALL,
    )

    # Паттерн для извлечения домена из карточки
    domain_re = re.compile(
        r'(?:href=["\']https?://([^"\'/?#]+)|([a-z0-9][a-z0-9\-]{0,61}[a-z0-9]?\.[a-z]{2,}))',
        re.IGNORECASE,
    )

    # Паттерн для даты публикации (ISO-8601 и популярные форматы)
    date_re = re.compile(
        r'(\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?)',
    )

    for match in card_re.finditer(html):
        card_html = match.group(1)
        card_text = _strip_html(card_html)

        # Ищем домен жертвы в карточке
        domain_match = domain_re.search(card_html)
        victim_domain = ""
        if domain_match:
            victim_domain = (domain_match.group(1) or domain_match.group(2) or "").lower()
            # Исключаем сам onion-адрес и служебные домены
            if "onion" in victim_domain or victim_domain in ("www", ""):
                victim_domain = ""

        # Ищем дату публикации
        date_match = date_re.search(card_text)
        published_at = date_match.group(1) if date_match else ""

        # Имя жертвы — первые значимые слова из текста карточки
        victim_name = card_text.strip()[:100].split("\n")[0].strip()

        if not victim_name:
            continue

        results.append({
            "victim": victim_name,
            "domain": victim_domain,
            "published_at": published_at,
            "group": group_name,
        })

    # Если паттерн карточек не сработал — пробуем найти по ссылкам /victim/ или /post/
    if not results:
        link_re = re.compile(
            r'<a[^>]+href="(/(?:victim|post|company|target)/([^"/?#]+))"[^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL,
        )
        for m in link_re.finditer(html):
            victim_slug = m.group(2)
            link_text = _strip_html(m.group(3))
            victim_name = link_text or victim_slug.replace("-", " ").replace("_", " ")

            # Ищем дату рядом со ссылкой (±200 символов контекста)
            start = max(0, m.start() - 200)
            end = min(len(html), m.end() + 200)
            context = html[start:end]
            date_match = date_re.search(context)
            published_at = date_match.group(1) if date_match else ""

            results.append({
                "victim": victim_name[:100],
                "domain": "",
                "published_at": published_at,
                "group": group_name,
            })

    return results


# ──────────────────────────────────────────────
# Агрегирующая функция мониторинга
# ──────────────────────────────────────────────

def monitor_ransomware_sites(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, Any]:
    """
    Итерирует по всем известным ransomware-сайтам, ищет упоминания домена.

    Алгоритм:
      1. Проверяем доступность Tor
      2. Если Tor недоступен — возвращаем {"error": ..., "tor_required": True}
      3. Для каждого сайта из ONION_SITES — скачиваем и парсим
      4. Совпадение = domain или его вариант найден в victim/domain поле
      5. Отправляем события в Core API через /api/v1/internal/ingest

    Возвращает:
        {
          "groups_checked": N,   — кол-во проверенных групп
          "found": M,            — кол-во найденных упоминаний
          "sent": K,             — успешно отправленных событий
          "tor_required": False, — всегда False при успешном запуске
        }
        или
        {
          "error": "Tor unavailable",
          "tor_required": True,
        }
    """
    domain_clean = _normalize_domain(domain)
    domain_variants = _extract_domain_variants(domain_clean)

    logger.info(
        "[ransomware_sites] Начало сканирования domain=%s (варианты: %s)",
        domain_clean,
        domain_variants,
    )

    # Проверяем доступность Tor перед началом работы
    if not check_tor_available():
        logger.warning(
            "[ransomware_sites] Tor недоступен — пропускаем onion-источники для %s",
            domain_clean,
        )
        return {"error": "Tor unavailable", "tor_required": True}

    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    ingest_headers: dict[str, str] = {"Authorization": f"Bearer {internal_secret}"}

    groups_checked = found = sent = 0

    # Создаём один Tor-клиент на всё сканирование
    tor_client = get_tor_client()
    if tor_client is None:
        logger.warning("[ransomware_sites] Не удалось создать Tor-клиент")
        return {"error": "Tor client creation failed", "tor_required": True}

    try:
        with tor_client:
            for group_name, onion_url in ONION_SITES.items():
                try:
                    victims = parse_ransomware_site(group_name, onion_url, tor_client)
                    groups_checked += 1

                    for victim in victims:
                        # Проверяем совпадение домена
                        searchable = (
                            victim.get("victim", "") + " " + victim.get("domain", "")
                        ).lower()

                        if not _domain_mentioned(searchable, domain_variants):
                            continue

                        found += 1
                        logger.info(
                            "[ransomware_sites] Совпадение! domain=%s group=%s victim=%s",
                            domain_clean,
                            group_name,
                            victim.get("victim", "?"),
                        )

                        # Формируем событие для Core API
                        event: dict[str, Any] = {
                            "event_type": "ransomware_mention",
                            "severity": "critical",
                            "source_type": "darknet_monitor",
                            "source_name": "ransomware_sites",
                            "target_domain": domain_clean,
                            "payload": {
                                "group": group_name,
                                "victim": victim.get("victim", ""),
                                "onion_url": onion_url,
                                "published_at": victim.get("published_at", ""),
                                "victim_domain": victim.get("domain", ""),
                            },
                        }

                        # Отправляем в Core API
                        if _send_ingest_event(ingest_url, ingest_headers, event):
                            sent += 1

                except Exception as exc:
                    # Ошибка одной группы не останавливает остальные
                    logger.error(
                        "[ransomware_sites][%s] Ошибка при сканировании: %s",
                        group_name,
                        exc,
                    )

    except Exception as exc:
        logger.error("[ransomware_sites] Ошибка Tor-клиента: %s", exc)

    logger.info(
        "[ransomware_sites] Итого domain=%s groups=%d found=%d sent=%d",
        domain_clean,
        groups_checked,
        found,
        sent,
    )

    return {
        "groups_checked": groups_checked,
        "found": found,
        "sent": sent,
        "tor_required": False,
    }


def _send_ingest_event(
    ingest_url: str,
    headers: dict[str, str],
    event: dict[str, Any],
) -> bool:
    """
    Отправляет событие в Core API.
    Возвращает True при успешной доставке (accepted или duplicate).
    Изолирована от исключений — не поднимает ошибки наружу.
    """
    try:
        response = httpx.post(
            ingest_url,
            json=event,
            headers=headers,
            timeout=10.0,  # clearnet — 10с достаточно
        )
        status_val: str = response.json().get("status", "error")
        return status_val in ("accepted", "duplicate")
    except Exception as exc:
        logger.error("[ransomware_sites] Ошибка отправки события в Core API: %s", exc)
        return False
