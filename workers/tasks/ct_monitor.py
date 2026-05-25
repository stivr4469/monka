"""
Certificate Transparency Monitor.

Опрашивает crt.sh API на наличие новых сертификатов для домена,
выявляет подозрительные имена (contains / levenshtein / wildcard_subdomain)
и отправляет события в Core API через bulk_ingest().
"""
import json
import logging
import os
from typing import Any

import httpx

from tasks.bulk_ingest import bulk_ingest

logger = logging.getLogger(__name__)

# Таймаут HTTP-запроса к crt.sh (секунды)
_CRT_TIMEOUT = 30.0

# Максимальный размер списка seen IDs (держим последние 1000)
_MAX_SEEN_IDS = 1000

# URL crt.sh API
_CRT_SH_URL = "https://crt.sh/"

# Порог расстояния Левенштейна для детектирования тайпосквота
_LEVENSHTEIN_THRESHOLD = 2


# ──────────────────────────────────────────────
# Вычисление расстояния Левенштейна (без внешних зависимостей)
# ──────────────────────────────────────────────

def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Вычисляет расстояние Левенштейна между двумя строками.

    Использует динамическое программирование с памятью O(min(len1, len2)).
    """
    # Короткая строка всегда s1 — экономим память
    if len(s1) > len(s2):
        s1, s2 = s2, s1

    len1, len2 = len(s1), len(s2)

    # Базовый случай: одна строка пустая
    if len1 == 0:
        return len2

    # Одна строка текущей строки DP
    prev = list(range(len2 + 1))

    for i in range(1, len1 + 1):
        curr = [i] + [0] * len2
        for j in range(1, len2 + 1):
            if s1[i - 1] == s2[j - 1]:
                cost = 0
            else:
                cost = 1
            curr[j] = min(
                curr[j - 1] + 1,       # вставка
                prev[j] + 1,           # удаление
                prev[j - 1] + cost,    # замена
            )
        prev = curr

    return prev[len2]


# ──────────────────────────────────────────────
# Вспомогательные функции
# ──────────────────────────────────────────────

def extract_domain_part(domain: str) -> str:
    """
    Извлекает «имя» домена без TLD.

    Примеры:
        example.com   → example
        sub.example.com → sub.example
        evil-example.ru → evil-example
    """
    dot_pos = domain.rfind(".")
    if dot_pos == -1:
        return domain
    return domain[:dot_pos]


def _strip_wildcard(name: str) -> str:
    """Убирает ведущий wildcard '*.', если есть."""
    if name.startswith("*."):
        return name[2:]
    return name


def is_suspicious(name: str, target_domain: str) -> tuple[bool, str]:
    """
    Определяет, является ли имя из сертификата подозрительным
    относительно целевого домена.

    Возвращает (suspicious: bool, method: str).

    Методы детектирования:
        wildcard_subdomain — wildcard покрывает домен напрямую (норма → False)
        contains           — имя содержит домен как подстроку (подозрительно)
        levenshtein        — малое расстояние до домена (без TLD)
    """
    name = name.strip().lower()
    target = target_domain.strip().lower()

    # Пропускаем сам целевой домен
    if name == target:
        return False, ""

    # Wildcard покрывает целевой домен напрямую: *.example.com для example.com
    # Это нормальный сертификат, не подозрительный
    if name == f"*.{target}":
        return False, "wildcard_subdomain"

    # Легитимный поддомен целевого домена: sub.example.com
    # (не wildcard, заканчивается на .{target})
    if name.endswith(f".{target}"):
        return False, ""

    # Убираем wildcard для дальнейшей проверки
    clean_name = _strip_wildcard(name)

    # Проверка contains: имя содержит домен как подстроку
    # Пример: evil-example.com содержит example.com → подозрительно
    # Пример: example.com.phish.ru содержит example.com → подозрительно
    if target in clean_name:
        return True, "contains"

    # Проверка Левенштейна: сравниваем части домена без TLD
    target_part = extract_domain_part(target)    # example
    name_part = extract_domain_part(clean_name)  # examp1e

    if name_part and levenshtein_distance(name_part, target_part) <= _LEVENSHTEIN_THRESHOLD:
        return True, "levenshtein"

    return False, ""


# ──────────────────────────────────────────────
# Работа с файлом seen IDs
# ──────────────────────────────────────────────

def _safe_domain_filename(domain: str) -> str:
    """Превращает домен в безопасное имя файла, заменяя точки на '_'."""
    return domain.replace(".", "_").replace("-", "_")


def load_seen_ids(domain: str) -> set[int]:
    """
    Загружает список уже обработанных cert ID из /tmp/ct_seen_{safe_domain}.json.
    Если файл не существует или повреждён — возвращает пустое множество.
    """
    path = f"/tmp/ct_seen_{_safe_domain_filename(domain)}.json"
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return set(int(x) for x in data)
    except FileNotFoundError:
        pass
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        logger.warning("[ct_monitor] Повреждён файл seen IDs %s: %s — сбрасываем", path, exc)
    return set()


def save_seen_ids(domain: str, ids: set[int]) -> None:
    """
    Сохраняет список seen IDs в /tmp/ct_seen_{safe_domain}.json.
    Держит только последние _MAX_SEEN_IDS записей (по возрастанию ID).
    """
    path = f"/tmp/ct_seen_{_safe_domain_filename(domain)}.json"
    # Сортируем и обрезаем: оставляем наибольшие ID (самые свежие)
    truncated = sorted(ids)[-_MAX_SEEN_IDS:]
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(truncated, fh)
    except OSError as exc:
        logger.error("[ct_monitor] Не удалось сохранить seen IDs для %s: %s", domain, exc)


# ──────────────────────────────────────────────
# Запрос к crt.sh
# ──────────────────────────────────────────────

def fetch_ct_certs(domain: str) -> list[dict]:
    """
    Получает список сертификатов для домена через crt.sh API.

    Запрос: GET https://crt.sh/?q=%.{domain}&output=json&deduplicate=Y
    Таймаут: _CRT_TIMEOUT секунд.

    Возвращает список dict с полями: id, name_value, not_before, issuer_name.
    При ошибке сети или неожиданном ответе — возвращает пустой список.
    """
    params = {
        "q": f"%.{domain}",
        "output": "json",
        "deduplicate": "Y",
    }
    try:
        with httpx.Client(timeout=_CRT_TIMEOUT) as client:
            resp = client.get(_CRT_SH_URL, params=params)

        if resp.status_code != 200:
            logger.warning(
                "[ct_monitor] crt.sh вернул статус %d для %s",
                resp.status_code, domain,
            )
            return []

        return resp.json()

    except httpx.TimeoutException:
        logger.warning("[ct_monitor] Таймаут запроса crt.sh для домена %s", domain)
        return []
    except Exception as exc:
        logger.error("[ct_monitor] Ошибка запроса crt.sh для %s: %s", domain, exc)
        return []


# ──────────────────────────────────────────────
# Основная функция
# ──────────────────────────────────────────────

def check_ct(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict[str, int]:
    """
    Основной pipeline Certificate Transparency Monitor.

    1. Получает сертификаты через crt.sh
    2. Фильтрует уже виденные ID (seen IDs из /tmp)
    3. Для каждого нового сертификата ищет подозрительные имена
    4. Отправляет события в Core API через bulk_ingest()
    5. Обновляет seen IDs

    Возвращает: {"checked": N_certs, "new": N_new, "suspicious": N_suspicious, "sent": N_sent}
    """
    domain = domain.strip().lower()
    logger.info("[ct_monitor] Начало проверки CT для domain=%s", domain)

    # Шаг 1: Получаем сертификаты
    certs = fetch_ct_certs(domain)
    if not certs:
        logger.info("[ct_monitor] domain=%s: сертификаты не получены", domain)
        return {"checked": 0, "new": 0, "suspicious": 0, "sent": 0}

    logger.info("[ct_monitor] domain=%s: получено %d сертификатов", domain, len(certs))

    # Шаг 2: Загружаем seen IDs и фильтруем новые
    seen_ids = load_seen_ids(domain)
    new_certs: list[dict] = []
    all_ids: set[int] = set()

    for cert in certs:
        try:
            cert_id = int(cert.get("id", 0))
        except (TypeError, ValueError):
            continue
        all_ids.add(cert_id)
        if cert_id not in seen_ids:
            new_certs.append(cert)

    logger.info(
        "[ct_monitor] domain=%s: новых сертификатов %d из %d",
        domain, len(new_certs), len(certs),
    )

    # Шаг 3: Анализируем новые сертификаты на подозрительные имена
    events: list[dict[str, Any]] = []

    for cert in new_certs:
        cert_id = int(cert.get("id", 0))
        issuer_name = cert.get("issuer_name", "")
        not_before = cert.get("not_before", "")
        raw_names = cert.get("name_value", "")

        # name_value может содержать несколько имён через \n
        names = [n.strip() for n in raw_names.split("\n") if n.strip()]

        for name in names:
            suspicious, method = is_suspicious(name, domain)
            if not suspicious:
                continue

            logger.warning(
                "[ct_monitor] Подозрительный сертификат: domain=%s name=%s cert_id=%d method=%s",
                domain, name, cert_id, method,
            )
            events.append({
                "event_type": "phishing_domain",
                "severity": "high",
                "source_type": "scanner",
                "source_name": "ct_monitor",
                "target_domain": domain,
                "payload": {
                    "suspicious_domain": name,
                    "cert_id": cert_id,
                    "issuer": issuer_name,
                    "issued_at": not_before,
                    "detection_method": method,
                },
            })

    # Шаг 4: Отправляем события в Core API
    sent = 0
    if events:
        result = bulk_ingest(events, core_api_url, internal_secret)
        sent = result.get("sent", 0)
        logger.info(
            "[ct_monitor] domain=%s отправлено событий: %d (ошибок: %d)",
            domain, sent, result.get("errors", 0),
        )

    # Шаг 5: Обновляем seen IDs (объединяем все ID из текущего запроса)
    seen_ids.update(all_ids)
    save_seen_ids(domain, seen_ids)

    logger.info(
        "[ct_monitor] Итого domain=%s checked=%d new=%d suspicious=%d sent=%d",
        domain, len(certs), len(new_certs), len(events), sent,
    )
    return {
        "checked": len(certs),
        "new": len(new_certs),
        "suspicious": len(events),
        "sent": sent,
    }
