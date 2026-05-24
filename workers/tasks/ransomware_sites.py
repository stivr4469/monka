"""
Парсер сайтов утечек ransomware-группировок через Tor.

Два режима:
  - httpx (быстро) — для сайтов со статическим HTML
  - Playwright (Chromium через Tor SOCKS5h) — для JS-rendered сайтов (LockBit3, Akira)

Tor-цепи ротируются через stem (NEWNYM) каждые N сайтов.
User-Agent ротируется через fake_useragent.

Безопасность:
  - shell=False везде, никаких subprocess
  - Никаких raw паролей или PII — только имена жертв/домены (публичные данные группировок)
"""
import logging
import re
import socket
from typing import Any

import httpx

from tasks.tor_client import check_tor_available, get_tor_client

logger = logging.getLogger(__name__)

_TOR_TIMEOUT = 45.0
_SNIPPET_MAX_LEN = 500
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WWW_RE = re.compile(r"^(https?://)?(www\.)?", re.IGNORECASE)

# ── Свежие .onion-адреса (май 2026, источник: ransomwatch/groups.json) ──────────
# Только группы с available=True в groups.json, по одному адресу на группу
ONION_SITES: dict[str, str] = {
    # LockBit 3.0 — крупнейшая RaaS, атаки на 2000+ организаций
    "lockbit3": "http://lockbit3753ekiocyo5epmpy6klmejchjtzddoekjlnt6mu3qh4de2id.onion",

    # RansomHouse — специализируется на двойном вымогательстве
    "ransomhouse": "http://zohlm7ahjwegcedoz7lrdrti7bvpofymcayotp744qhx6gjmxbuo2yid.onion",

    # Medusa — активна с 2023, атакует критическую инфраструктуру
    "medusa": "http://xfv4jzckytb4g3ckwemcny3ihv4i5p4lqzdpi624cxisu35my5fwi5qd.onion",

    # Clop — специализируется на MOVEit, GoAnywhere (Shell.com 2021)
    "clop": "http://santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad.onion",

    # RansomEXX — атакует государственные структуры и банки
    "ransomexx": "http://rnsm777cdsjrsdlbs4v5qoeppu3px6sb2igmh53jzrx7ipcrbjz5b2ad.onion",

    # Everest — специализируется на данных сотрудников
    "everest": "http://ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad.onion",

    # Akira — JS-rendered, атакует VMware ESXi
    "akira": "http://akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion",

    # Play (PlayCrypt) — отказывается от RaaS-модели
    "play": "http://k7kg3jqxang3wh7hnmaiokchk7qoebupfgoik6rha6mjpzwupwtj25yd.onion",

    # Hunters International — наследник Hive
    "hunters": "http://hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejyid.onion",

    # Rhysida — атакует healthcare и образование
    "rhysida": "http://rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad.onion",

    # Stormous — атаки на правительственные ресурсы
    "stormous": "http://pdcizqzjitsgfcgqeyhuee5u6uki6zy5slzioinlhx6xjnsw25irdgqd.onion",
}

# Сайты, которые рендерят жертв через JavaScript — нужен Playwright
_JS_RENDERED_GROUPS = {"lockbit3", "akira"}


def _normalize_domain(domain: str) -> str:
    return _WWW_RE.sub("", domain.strip()).lower().rstrip("/")


def _strip_html(text: str) -> str:
    return _HTML_TAG_RE.sub(" ", text).strip()


def _extract_domain_variants(domain: str) -> list[str]:
    clean = _normalize_domain(domain)
    root = clean.split(".")[0]
    return list(dict.fromkeys([clean, f"www.{clean}", root]))


def _domain_mentioned(text: str, variants: list[str]) -> bool:
    text_lower = text.lower()
    return any(v in text_lower for v in variants)


def _get_random_ua() -> str:
    """Возвращает случайный Chrome User-Agent."""
    try:
        from fake_useragent import UserAgent
        return UserAgent().chrome
    except Exception:
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )


def _rotate_tor_circuit() -> None:
    """Запрашивает новую Tor-цепь через stem (NEWNYM)."""
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(port=9051) as ctrl:
            ctrl.authenticate()
            ctrl.signal(Signal.NEWNYM)
            logger.info("[ransomware_sites] Tor-цепь обновлена (NEWNYM)")
    except Exception as exc:
        logger.debug("[ransomware_sites] NEWNYM недоступен: %s", exc)


def _fetch_with_playwright(onion_url: str, group_name: str) -> str:
    """
    Загружает страницу через Playwright + Chromium + Tor SOCKS5h.
    Ждёт JS-рендеринга, возвращает итоговый HTML.
    """
    try:
        from playwright.sync_api import sync_playwright
        from playwright_stealth import Stealth
    except ImportError as exc:
        logger.error("[ransomware_sites] Playwright не установлен: %s", exc)
        return ""

    ua = _get_random_ua()
    html = ""
    stealth = Stealth()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                proxy={"server": "socks5://127.0.0.1:9050"},
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            ctx = browser.new_context(
                user_agent=ua,
                locale="en-US",
                timezone_id="America/New_York",
                viewport={"width": 1366, "height": 768},
            )
            page = ctx.new_page()
            stealth.apply_stealth_sync(page)

            logger.info("[ransomware_sites][%s][playwright] GET %s", group_name, onion_url)
            page.goto(onion_url, timeout=int(_TOR_TIMEOUT * 1000), wait_until="networkidle")

            # Ждём появления контента жертв (если не загрузился — берём что есть)
            try:
                page.wait_for_selector(
                    "div[class*='victim'], li[class*='victim'], "
                    "div[class*='company'], a[href*='/post/'], a[href*='/victim/']",
                    timeout=15000,
                )
            except Exception:
                pass  # возьмём page.content() как есть

            html = page.content()
            ctx.close()
            browser.close()

        # Удаляем артефакты Playwright из /tmp
        import glob, shutil
        for path in glob.glob("/tmp/playwright-artifacts-*"):
            shutil.rmtree(path, ignore_errors=True)

    except Exception as exc:
        logger.warning(
            "[ransomware_sites][%s][playwright] Ошибка: %s", group_name, exc
        )

    return html


def parse_ransomware_site(
    group_name: str,
    onion_url: str,
    tor_client: "httpx.Client | None",
) -> list[dict[str, Any]]:
    """
    Загружает страницу .onion-сайта и возвращает список жертв.

    Выбирает режим автоматически:
      - JS_RENDERED_GROUPS → Playwright
      - остальные          → httpx через Tor SOCKS5h
    """
    results: list[dict[str, Any]] = []

    if group_name in _JS_RENDERED_GROUPS:
        html = _fetch_with_playwright(onion_url, group_name)
    else:
        if tor_client is None:
            return []
        try:
            resp = tor_client.get(onion_url, timeout=_TOR_TIMEOUT)
            if resp.status_code != 200:
                logger.warning(
                    "[ransomware_sites][%s] HTTP %d", group_name, resp.status_code
                )
                return []
            html = resp.text
        except httpx.TimeoutException:
            logger.warning("[ransomware_sites][%s] Таймаут", group_name)
            return []
        except httpx.ConnectError as exc:
            logger.warning("[ransomware_sites][%s] ConnectError: %s", group_name, exc)
            return []
        except Exception as exc:
            logger.warning("[ransomware_sites][%s] Ошибка: %s", group_name, exc)
            return []

    if html:
        results = _parse_victims_from_html(html, group_name)
        logger.info(
            "[ransomware_sites][%s] Найдено жертв: %d", group_name, len(results)
        )

    return results


_JS_NOISE_RE = re.compile(
    r'^[\s\{\}\[\]();,<>@#!$%^&*+=|\\/?~`\'\"]+$'
    r'|^\.[\w\-]'              # CSS класс
    r'|^[a-z]+\s*[:=]\s*'     # CSS свойство или JS присвоение
    r'|^https?://'             # голая ссылка
    r'|\bfunction\b|\bvar\b|\bconst\b|\blet\b|\breturn\b'
    r'|\{|\}|=>|&&|\|\|',
)
_COMPANY_RE = re.compile(r'[A-ZА-Я]')  # хотя бы одна заглавная буква


def _is_real_victim(text: str) -> bool:
    """Отфильтровывает CSS/JS мусор, оставляет названия компаний."""
    t = text.strip()
    if len(t) < 4 or len(t) > 120:
        return False
    if _JS_NOISE_RE.search(t):
        return False
    if not _COMPANY_RE.search(t):
        return False
    # Отсеиваем числовые строки и таймеры вида "247D 01h 30m 02s"
    if re.match(r'^[\d\s:hmsHMSdD]+$', t):
        return False
    if re.search(r'\d+[hH]\s*\d+[mM]|\d+[dD]\s+\d+[hH]', t):
        return False
    return True


def _parse_victims_from_html(html: str, group_name: str) -> list[dict[str, Any]]:
    """
    Парсер HTML ransomware-сайтов.

    Сначала пробуем специфичный парсер для группы (самый точный),
    затем универсальный эвристический через BeautifulSoup.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return _parse_victims_regex_fallback(html, group_name)

    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript", "head"]):
        tag.decompose()

    # Специфичные парсеры для известных сайтов
    if group_name in ("lockbit3", "lockbit3_fs"):
        return _parse_lockbit3(soup, group_name)
    if group_name == "medusa":
        return _parse_medusa(soup)

    # Универсальный парсер
    return _parse_generic(soup, group_name)


_DOMAIN_RE = re.compile(r'^[a-z0-9][a-z0-9\-\.]{2,61}\.[a-z]{2,10}$', re.IGNORECASE)


def _parse_lockbit3(soup: Any, group_name: str) -> list[dict[str, Any]]:
    """
    LockBit 3.0: карточки a.post-block
    Имя/домен жертвы: div.post-title (часто это домен, напр. "jackpotjunction.com")
    Дата: div.updated-post-date
    """
    results = []
    seen: set[str] = set()

    for post in soup.find_all("a", class_=re.compile(r"\bpost-block\b")):
        title_el = post.find(class_="post-title")
        date_el  = post.find(class_="updated-post-date")

        name = title_el.get_text(strip=True) if title_el else ""
        if not name or name in seen:
            continue
        # Принимаем: домен (jackpotjunction.com) ИЛИ имя компании (содержит пробел)
        is_domain = bool(_DOMAIN_RE.match(name))
        is_company = " " in name or _COMPANY_RE.search(name)
        if not (is_domain or is_company):
            continue
        seen.add(name)

        date_text = date_el.get_text(strip=True) if date_el else ""
        dm = re.search(r"(\d{2}\s+\w+,?\s+\d{4}|\d{4}-\d{2}-\d{2})", date_text)

        results.append({
            "victim": name[:120],
            "domain": name if is_domain else "",
            "published_at": dm.group(1) if dm else date_text[:40],
            "group": group_name,
        })

    return results


def _parse_medusa(soup: Any) -> list[dict[str, Any]]:
    """
    Medusa: карточки с именем жертвы в h3 или .company-name
    """
    results = []
    seen: set[str] = set()
    date_re = re.compile(r"(\d{4}-\d{2}-\d{2})")

    for card in soup.find_all(["div", "li", "article"], limit=300):
        h = card.find(["h3", "h4"])
        if not h:
            continue
        name = h.get_text(strip=True)
        if not name or name in seen or not _is_real_victim(name):
            continue
        seen.add(name)
        date_m = date_re.search(card.get_text())
        results.append({
            "victim": name[:120],
            "domain": "",
            "published_at": date_m.group(1) if date_m else "",
            "group": "medusa",
        })
    return results


def _parse_generic(soup: Any, group_name: str) -> list[dict[str, Any]]:
    """Универсальный эвристический парсер через классы и заголовки."""
    results = []
    seen: set[str] = set()
    date_re = re.compile(r"(\d{4}-\d{2}-\d{2})")
    domain_re = re.compile(
        r'href=["\']https?://([^"\'/?#\s]{4,})',
        re.IGNORECASE,
    )

    _CARD_CLASSES = re.compile(
        r"victim|company|target|post|entry|blog|leak|item|card",
        re.IGNORECASE,
    )

    cards = [
        t for t in soup.find_all(["div", "li", "article", "section"], limit=600)
        if any(_CARD_CLASSES.search(c) for c in t.get("class", []))
    ]
    if not cards:
        cards = soup.find_all(["h2", "h3", "h4"], limit=300)

    for card in cards:
        card_text = card.get_text(separator=" ", strip=True)
        first_line = card_text.split("\n")[0].strip()[:120]
        if not first_line or first_line in seen or not _is_real_victim(first_line):
            continue
        seen.add(first_line)

        victim_domain = ""
        dm = domain_re.search(str(card))
        if dm:
            cand = dm.group(1).lower()
            if "onion" not in cand:
                victim_domain = cand

        date_m = date_re.search(card_text)
        results.append({
            "victim": first_line,
            "domain": victim_domain,
            "published_at": date_m.group(1) if date_m else "",
            "group": group_name,
        })
    return results


def _parse_victims_regex_fallback(html: str, group_name: str) -> list[dict[str, Any]]:
    """Fallback без BeautifulSoup."""
    results = []
    card_re = re.compile(
        r'<(?:div|li|article)[^>]*class="[^"]*(?:victim|company|post|entry)[^"]*"[^>]*>'
        r'(.*?)</(?:div|li|article)>',
        re.IGNORECASE | re.DOTALL,
    )
    for match in card_re.finditer(html):
        text = _strip_html(match.group(1)).strip()[:120].split("\n")[0].strip()
        if _is_real_victim(text):
            results.append({"victim": text, "domain": "", "published_at": "", "group": group_name})
    return results


def monitor_ransomware_sites(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, Any]:
    """
    Проверяет все ransomware-сайты на упоминание домена.

    Возвращает статистику: groups_checked, found, sent, tor_required.
    """
    domain_clean = _normalize_domain(domain)
    domain_variants = _extract_domain_variants(domain_clean)

    logger.info(
        "[ransomware_sites] Начало сканирования domain=%s (варианты: %s)",
        domain_clean,
        domain_variants,
    )

    if not check_tor_available():
        logger.warning(
            "[ransomware_sites] Tor недоступен — пропускаем onion-источники для %s",
            domain_clean,
        )
        return {"error": "Tor unavailable", "tor_required": True}

    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    ingest_headers = {"Authorization": f"Bearer {internal_secret}"}

    groups_checked = found = sent = 0

    tor_client = get_tor_client()
    if tor_client is None:
        return {"error": "Tor client creation failed", "tor_required": True}

    try:
        with tor_client:
            for i, (group_name, onion_url) in enumerate(ONION_SITES.items()):
                # Ротируем Tor-цепь каждые 3 сайта
                if i > 0 and i % 3 == 0:
                    _rotate_tor_circuit()

                try:
                    victims = parse_ransomware_site(group_name, onion_url, tor_client)
                    groups_checked += 1

                    for victim in victims:
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

                        event: dict[str, Any] = {
                            "event_type": "ransomware_mention",
                            "severity": "critical",
                            "source_type": "darknet",
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

                        if _send_ingest_event(ingest_url, ingest_headers, event):
                            sent += 1

                except Exception as exc:
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
    try:
        response = httpx.post(ingest_url, json=event, headers=headers, timeout=10.0)
        status_val: str = response.json().get("status", "error")
        return status_val in ("accepted", "duplicate")
    except Exception as exc:
        logger.error("[ransomware_sites] Ошибка отправки в Core API: %s", exc)
        return False


def run_darknet_monitor_all_assets() -> None:
    """
    10.H: Celery Beat задача — мониторинг ransomware-сайтов для всех активных активов.

    Запрашивает список активов через Core API и проверяет каждый на упоминание
    в известных ransomware-сайтах даркнета.
    Запускается каждый час через Beat расписание.
    """
    import os

    import httpx

    core_url = os.environ.get("CORE_API_URL", "http://core:8000")
    internal_secret = os.environ.get("INTERNAL_API_SECRET", "")

    try:
        resp = httpx.get(
            f"{core_url}/api/v1/assets/",
            headers={"Authorization": f"Bearer {internal_secret}"},
            timeout=10,
        )
        assets = resp.json() if resp.is_success else []
        logger.info("[beat] darknet-monitor-all: запускаем для %d активов", len(assets))
        for asset in assets:
            domain = asset.get("domain") if isinstance(asset, dict) else None
            if domain:
                try:
                    monitor_ransomware_sites(
                        domain=domain,
                        core_api_url=core_url,
                        internal_secret=internal_secret,
                    )
                except Exception as exc:
                    logger.warning("[beat] darknet-monitor-all: ошибка для %s: %s", domain, exc)
    except Exception as exc:
        logger.warning("[beat] darknet-monitor-all: ошибка получения активов: %s", exc)
