"""
Тесты Certificate Transparency Monitor — задача 12.A.

Покрывает:
  - levenshtein_distance: базовые случаи
  - is_suspicious: contains, levenshtein, wildcard_subdomain (ok), легитимный поддомен (ok)
  - fetch_ct_certs: мок httpx — success, timeout, non-200
  - check_ct: новые сертификаты → события; seen IDs → пропуск; пустой ответ → 0 событий
  - API: 202 accepted, 422 неверный домен, 401 без токена
"""
# sys.path для workers добавляется в conftest.py
import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient

# Импортируем функции воркера напрямую
from tasks.ct_monitor import (
    check_ct,
    extract_domain_part,
    fetch_ct_certs,
    is_suspicious,
    levenshtein_distance,
    load_seen_ids,
    save_seen_ids,
)

CT_SCAN_URL = "/api/v1/scan/ct"

# Путь к функции воркера в контексте эндпоинта (патчим там, где используется)
_WORKER_PATH = "app.api.v1.endpoints.ct_scan.check_ct"


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ─── levenshtein_distance ─────────────────────────────────────────────────────

def test_levenshtein_equal_strings():
    """Расстояние между одинаковыми строками равно 0."""
    assert levenshtein_distance("example", "example") == 0


def test_levenshtein_one_insertion():
    """Одна вставка — расстояние 1."""
    assert levenshtein_distance("exmple", "example") == 1


def test_levenshtein_one_substitution():
    """Одна замена — расстояние 1."""
    # examp1e → example (1 → l)
    assert levenshtein_distance("examp1e", "example") == 1


def test_levenshtein_two_substitutions():
    """Два изменения — расстояние 2."""
    # visa → v1s4 (2 замены: i→1, a→4)
    assert levenshtein_distance("v1s4", "visa") == 2


def test_levenshtein_empty_string():
    """Пустая строка против непустой — расстояние равно длине второй."""
    assert levenshtein_distance("", "hello") == 5
    assert levenshtein_distance("hello", "") == 5


def test_levenshtein_completely_different():
    """Полностью разные строки короткой длины."""
    assert levenshtein_distance("abc", "xyz") == 3


# ─── extract_domain_part ──────────────────────────────────────────────────────

def test_extract_domain_part_simple():
    """example.com → example."""
    assert extract_domain_part("example.com") == "example"


def test_extract_domain_part_subdomain():
    """sub.example.com → sub.example."""
    assert extract_domain_part("sub.example.com") == "sub.example"


def test_extract_domain_part_no_dot():
    """Строка без точки возвращается как есть."""
    assert extract_domain_part("localhost") == "localhost"


# ─── is_suspicious ────────────────────────────────────────────────────────────

def test_is_suspicious_contains_evil_prefix():
    """evil-example.com содержит example.com → подозрительно, метод contains."""
    suspicious, method = is_suspicious("evil-example.com", "example.com")
    assert suspicious is True
    assert method == "contains"


def test_is_suspicious_contains_suffix():
    """example.com.phish.ru содержит example.com → подозрительно."""
    suspicious, method = is_suspicious("example.com.phish.ru", "example.com")
    assert suspicious is True
    assert method == "contains"


def test_is_suspicious_levenshtein_typo():
    """examp1e.com — расстояние Левенштейна 1 к example → подозрительно."""
    suspicious, method = is_suspicious("examp1e.com", "example.com")
    assert suspicious is True
    assert method == "levenshtein"


def test_is_suspicious_levenshtein_distance_2():
    """exampie.com — замена l→i, расстояние 1 → подозрительно."""
    suspicious, method = is_suspicious("exampie.com", "example.com")
    assert suspicious is True
    assert method == "levenshtein"


def test_is_suspicious_wildcard_direct():
    """*.example.com — wildcard для самого домена — НЕ подозрительно."""
    suspicious, method = is_suspicious("*.example.com", "example.com")
    assert suspicious is False
    assert method == "wildcard_subdomain"


def test_is_suspicious_legitimate_subdomain():
    """api.example.com — легитимный поддомен — НЕ подозрительно."""
    suspicious, method = is_suspicious("api.example.com", "example.com")
    assert suspicious is False


def test_is_suspicious_exact_match():
    """Сам домен — НЕ подозрительный."""
    suspicious, _ = is_suspicious("example.com", "example.com")
    assert suspicious is False


def test_is_suspicious_completely_different():
    """Полностью другой домен без совпадений — НЕ подозрительный."""
    suspicious, _ = is_suspicious("google.com", "example.com")
    assert suspicious is False


# ─── fetch_ct_certs ───────────────────────────────────────────────────────────

def test_fetch_ct_certs_success():
    """Успешный ответ crt.sh → список сертификатов."""
    fake_certs = [
        {"id": 1, "name_value": "example.com", "not_before": "2026-01-01", "issuer_name": "Let's Encrypt"},
    ]
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_certs

    with patch("tasks.ct_monitor.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_client.get.return_value = mock_resp
        result = fetch_ct_certs("example.com")

    assert result == fake_certs


def test_fetch_ct_certs_timeout():
    """Таймаут запроса → возвращает пустой список."""
    import httpx as real_httpx

    with patch("tasks.ct_monitor.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_client.get.side_effect = real_httpx.TimeoutException("timeout")
        result = fetch_ct_certs("example.com")

    assert result == []


def test_fetch_ct_certs_non_200():
    """Ответ crt.sh с кодом != 200 → возвращает пустой список."""
    mock_resp = MagicMock()
    mock_resp.status_code = 503

    with patch("tasks.ct_monitor.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_client.get.return_value = mock_resp
        result = fetch_ct_certs("example.com")

    assert result == []


# ─── check_ct ────────────────────────────────────────────────────────────────

def _make_cert(cert_id: int, name_value: str, issuer: str = "Test CA") -> dict:
    """Хелпер для создания тестового сертификата."""
    return {
        "id": cert_id,
        "name_value": name_value,
        "not_before": "2026-05-01 00:00:00",
        "issuer_name": issuer,
    }


def test_check_ct_new_suspicious_cert_sends_event():
    """Новый подозрительный сертификат → событие отправляется через bulk_ingest."""
    certs = [_make_cert(100, "evil-example.com")]

    with patch("tasks.ct_monitor.fetch_ct_certs", return_value=certs), \
         patch("tasks.ct_monitor.load_seen_ids", return_value=set()), \
         patch("tasks.ct_monitor.save_seen_ids") as mock_save, \
         patch("tasks.ct_monitor.bulk_ingest", return_value={"sent": 1, "errors": 0}) as mock_ingest:

        result = check_ct("example.com", "http://core:8000", "secret")

    assert result["checked"] == 1
    assert result["new"] == 1
    assert result["suspicious"] == 1
    assert result["sent"] == 1

    # Проверяем структуру отправленного события
    call_args = mock_ingest.call_args[0]
    events = call_args[0]
    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "phishing_domain"
    assert event["severity"] == "high"
    assert event["source_name"] == "ct_monitor"
    assert event["payload"]["suspicious_domain"] == "evil-example.com"
    assert event["payload"]["detection_method"] == "contains"


def test_check_ct_seen_ids_skips_cert():
    """Сертификат с уже виденным ID → не отправляется."""
    certs = [_make_cert(42, "evil-example.com")]

    with patch("tasks.ct_monitor.fetch_ct_certs", return_value=certs), \
         patch("tasks.ct_monitor.load_seen_ids", return_value={42}), \
         patch("tasks.ct_monitor.save_seen_ids"), \
         patch("tasks.ct_monitor.bulk_ingest") as mock_ingest:

        result = check_ct("example.com", "http://core:8000", "secret")

    assert result["new"] == 0
    assert result["suspicious"] == 0
    # bulk_ingest не должен вызываться если нет событий
    mock_ingest.assert_not_called()


def test_check_ct_empty_response_returns_zeros():
    """Пустой ответ crt.sh → все счётчики равны 0."""
    with patch("tasks.ct_monitor.fetch_ct_certs", return_value=[]):
        result = check_ct("example.com", "http://core:8000", "secret")

    assert result == {"checked": 0, "new": 0, "suspicious": 0, "sent": 0}


def test_check_ct_legitimate_cert_not_sent():
    """Легитимный поддомен (api.example.com) не вызывает событие."""
    certs = [_make_cert(200, "api.example.com")]

    with patch("tasks.ct_monitor.fetch_ct_certs", return_value=certs), \
         patch("tasks.ct_monitor.load_seen_ids", return_value=set()), \
         patch("tasks.ct_monitor.save_seen_ids"), \
         patch("tasks.ct_monitor.bulk_ingest") as mock_ingest:

        result = check_ct("example.com", "http://core:8000", "secret")

    assert result["suspicious"] == 0
    mock_ingest.assert_not_called()


def test_check_ct_multiple_names_in_cert():
    """Сертификат с несколькими именами в name_value — проверяются все."""
    # Один легитимный поддомен и один подозрительный в одном сертификате
    certs = [_make_cert(300, "api.example.com\nevil-example.com")]

    with patch("tasks.ct_monitor.fetch_ct_certs", return_value=certs), \
         patch("tasks.ct_monitor.load_seen_ids", return_value=set()), \
         patch("tasks.ct_monitor.save_seen_ids"), \
         patch("tasks.ct_monitor.bulk_ingest", return_value={"sent": 1, "errors": 0}):

        result = check_ct("example.com", "http://core:8000", "secret")

    # Только подозрительное имя создаёт событие
    assert result["suspicious"] == 1


# ─── API тесты ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ct_scan_accepted(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Валидный домен → 202 Accepted с полями status и domain."""
    with patch(_WORKER_PATH, return_value={"checked": 5, "new": 2, "suspicious": 1, "sent": 1}):
        resp = await client.post(
            CT_SCAN_URL,
            json={"domain": "example.com"},
            headers=_auth_headers(superuser_token),
        )

    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["domain"] == "example.com"


@pytest.mark.asyncio
async def test_ct_scan_invalid_domain_special_chars(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Домен со специальными символами → 422 Unprocessable Entity."""
    resp = await client.post(
        CT_SCAN_URL,
        json={"domain": "evil/../etc/passwd"},
        headers=_auth_headers(superuser_token),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ct_scan_invalid_domain_empty(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Пустой домен → 422 Unprocessable Entity."""
    resp = await client.post(
        CT_SCAN_URL,
        json={"domain": ""},
        headers=_auth_headers(superuser_token),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ct_scan_requires_auth(client: AsyncClient) -> None:
    """Запрос без токена → 401 Unauthorized."""
    resp = await client.post(
        CT_SCAN_URL,
        json={"domain": "example.com"},
    )
    assert resp.status_code == 401
