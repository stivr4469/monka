"""
Детектор фишинговых/тайпосквот доменов.

Генерирует варианты целевого домена шестью техниками и проверяет,
резолвится ли каждый вариант — резолв означает потенциальный фишинг.
Найденные домены отправляются в Core API через bulk_ingest().
"""
import logging
import socket
from typing import Any

from tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

# Таймаут DNS-резолва (секунды)
_RESOLVE_TIMEOUT = 2

# Максимальная длина варианта домена (с учётом TLD)
_MAX_VARIANT_LEN = 60

# Таблица замены гласных для техники vowel_swap
_VOWEL_MAP: dict[str, str] = {
    "a": "4",
    "e": "3",
    "i": "1",
    "o": "0",
}

# Альтернативные TLD для техники tld_swap
_ALT_TLDS: list[str] = [".net", ".org", ".io", ".co"]

# Префиксы для техники prefix_add
_PREFIXES: list[str] = ["secure", "login", "my"]


# ──────────────────────────────────────────────
# Генераторы вариантов
# ──────────────────────────────────────────────

def _vowel_swap(name: str) -> list[tuple[str, str]]:
    """Заменяет каждую гласную на цифровой омоглиф (a→4, e→3, i→1, o→0).
    Возвращает пары (вариант_имени, описание_техники)."""
    results = []
    for i, ch in enumerate(name):
        if ch in _VOWEL_MAP:
            variant = name[:i] + _VOWEL_MAP[ch] + name[i + 1:]
            results.append((variant, "vowel_swap"))
    return results


def _char_omission(name: str) -> list[tuple[str, str]]:
    """Убирает одну букву на каждой позиции."""
    results = []
    for i in range(len(name)):
        variant = name[:i] + name[i + 1:]
        if variant:  # не создаём пустое имя
            results.append((variant, "char_omission"))
    return results


def _char_duplication(name: str) -> list[tuple[str, str]]:
    """Удваивает каждую букву по очереди."""
    results = []
    for i, ch in enumerate(name):
        variant = name[:i] + ch + name[i:]
        results.append((variant, "char_duplication"))
    return results


def _hyphen_insert(name: str) -> list[tuple[str, str]]:
    """Вставляет дефис между каждой парой символов."""
    results = []
    # Вставляем дефис после каждого символа кроме последнего
    for i in range(1, len(name)):
        variant = name[:i] + "-" + name[i:]
        results.append((variant, "hyphen_insert"))
    return results


def _tld_swap(name: str, original_tld: str) -> list[tuple[str, str]]:
    """Подставляет альтернативные TLD вместо оригинального."""
    results = []
    for tld in _ALT_TLDS:
        if tld != original_tld:
            # Вариант уже включает TLD — возвращаем полный домен
            results.append((name + tld, "tld_swap"))
    return results


def _prefix_add(name: str, original_tld: str) -> list[tuple[str, str]]:
    """Добавляет типичный фишинговый префикс через дефис."""
    results = []
    for prefix in _PREFIXES:
        variant = prefix + "-" + name + original_tld
        results.append((variant, "prefix_add"))
    return results


# ──────────────────────────────────────────────
# DNS-резолв
# ──────────────────────────────────────────────

def _try_resolve(variant: str) -> str | None:
    """
    Пробует разрезолвить домен. Возвращает первый IP или None.
    Таймаут: _RESOLVE_TIMEOUT секунд. Исключения не пробрасываются.
    """
    try:
        socket.setdefaulttimeout(_RESOLVE_TIMEOUT)
        results = socket.getaddrinfo(variant, None)
        if results:
            return results[0][4][0]  # первый IP-адрес
    except (socket.gaierror, socket.herror, OSError):
        pass  # домен не резолвится — это ожидаемо для большинства вариантов
    except Exception as exc:
        logger.debug("[phishing] Неожиданная ошибка резолва %s: %s", variant, exc)
    finally:
        socket.setdefaulttimeout(None)  # восстанавливаем глобальный таймаут
    return None


# ──────────────────────────────────────────────
# Основная функция
# ──────────────────────────────────────────────

def detect_phishing_domains(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, int]:
    """
    Генерирует тайпосквот-варианты домена и проверяет каждый через DNS.

    Резолвящиеся варианты отправляются в Core API как события с типом
    'phishing_domain' и severity='high'.

    Возвращает: {"checked": N, "found": M, "sent": K}
    """
    domain = domain.strip().lower()
    logger.info("[phishing] Начало проверки тайпосквота domain=%s", domain)

    # Разбиваем домен на имя и TLD (берём последнюю точку как разделитель)
    dot_pos = domain.rfind(".")
    if dot_pos == -1:
        # Домен без точки — нечего проверять
        logger.warning("[phishing] Домен без TLD: %s — пропускаем", domain)
        return {"checked": 0, "found": 0, "sent": 0}

    name = domain[:dot_pos]          # например, "visa"
    original_tld = domain[dot_pos:]  # например, ".com"

    # ── Собираем все варианты ──
    # Техники, работающие с именем (без TLD)
    name_variants: list[tuple[str, str]] = []
    name_variants.extend(_vowel_swap(name))
    name_variants.extend(_char_omission(name))
    name_variants.extend(_char_duplication(name))
    name_variants.extend(_hyphen_insert(name))

    # Преобразуем в полные домены: добавляем оригинальный TLD
    full_variants: list[tuple[str, str]] = [
        (v + original_tld, tech) for v, tech in name_variants
    ]

    # Техника tld_swap: подставляем другие TLD к оригинальному имени
    tld_variants = _tld_swap(name, original_tld)
    full_variants.extend(tld_variants)

    # Техника prefix_add: добавляем префикс к полному имени+TLD
    prefix_variants = _prefix_add(name, original_tld)
    full_variants.extend(prefix_variants)

    # ── Дедупликация и фильтрация ──
    seen: set[str] = {domain}  # исключаем оригинальный домен
    filtered: list[tuple[str, str]] = []
    for variant_domain, tech in full_variants:
        if variant_domain in seen:
            continue
        if len(variant_domain) > _MAX_VARIANT_LEN:
            # Пропускаем слишком длинные варианты
            logger.debug("[phishing] Пропуск слишком длинного варианта: %s", variant_domain)
            continue
        seen.add(variant_domain)
        filtered.append((variant_domain, tech))

    logger.info("[phishing] domain=%s сгенерировано %d уникальных вариантов", domain, len(filtered))

    # ── Проверяем резолв каждого варианта ──
    events: list[dict[str, Any]] = []
    for variant_domain, technique in filtered:
        resolved_ip = _try_resolve(variant_domain)
        if resolved_ip:
            logger.warning(
                "[phishing] Тайпосквот резолвится! %s → %s (техника: %s, IP: %s)",
                domain, variant_domain, technique, resolved_ip,
            )
            events.append({
                "event_type": "phishing_domain",
                "severity": "high",
                "source_type": "osint",
                "source_name": "phishing_detector",
                "target_domain": domain,
                "payload": {
                    "domain": variant_domain,
                    "original": domain,
                    "type": technique,
                    "technique": technique,
                    "resolved_ip": resolved_ip,
                },
            })

    # ── Батчевая отправка найденных событий ──
    sent = 0
    if events:
        result = bulk_ingest(events, core_api_url, internal_secret)
        sent = result.get("sent", 0)
        logger.info(
            "[phishing] domain=%s отправлено событий: %d (ошибок: %d)",
            domain, sent, result.get("errors", 0),
        )

    logger.info(
        "[phishing] Итого domain=%s checked=%d found=%d sent=%d",
        domain, len(filtered), len(events), sent,
    )
    return {"checked": len(filtered), "found": len(events), "sent": sent}
