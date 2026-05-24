"""
Тесты валидатора сессионных кук (задача 9.C).

Покрывает:
- Парсинг Netscape-формата
- Парсинг JSON-формата
- Определение redirect на страницу логина
- Маскирование значений кук
- Итерацию cookie-файлов из ZIP
- Проверку активности сессий (с мокированием httpx)
- Основную функцию validate_cookies_from_zip (e2e с ZIP)
- Эндпоинт POST /api/v1/scan/cookies
"""
import io
import json
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# sys.path для workers добавляется в conftest.py
from tasks.cookie_validator import (
    _check_cookie_alive,
    _is_login_redirect,
    _iter_cookie_files,
    _mask_cookie_value,
    _parse_json_cookies,
    _parse_netscape_cookies,
    validate_cookies_from_zip,
)


# ──────────────────────────────────────────────
# Парсинг Netscape-формата
# ──────────────────────────────────────────────

NETSCAPE_VALID = """\
# Netscape HTTP Cookie File
# Этот файл создан браузером. Не редактируйте.

.example.com\tTRUE\t/\tFALSE\t1893456000\tsessionid\tabc123def456ghi789
.example.com\tTRUE\t/\tTRUE\t0\tcf_clearance\txyz987tuvwxy
mail.google.com\tFALSE\t/\tTRUE\t1893456000\t__Secure-3PSID\tgoogletoken
"""

def test_parse_netscape_basic():
    cookies = _parse_netscape_cookies(NETSCAPE_VALID)
    assert len(cookies) == 3

def test_parse_netscape_fields():
    cookies = _parse_netscape_cookies(NETSCAPE_VALID)
    session = next(c for c in cookies if c["name"] == "sessionid")
    assert session["host"] == ".example.com"
    assert session["value"] == "abc123def456ghi789"
    assert session["path"] == "/"
    assert session["expiry"] == 1893456000
    assert session["secure"] is False

def test_parse_netscape_secure_flag():
    cookies = _parse_netscape_cookies(NETSCAPE_VALID)
    clearance = next(c for c in cookies if c["name"] == "cf_clearance")
    assert clearance["secure"] is True

def test_parse_netscape_skip_comments():
    """Строки начинающиеся на # должны быть пропущены."""
    text = "# Netscape HTTP Cookie File\n# comment\n.host.com\tFALSE\t/\tFALSE\t0\tname\tval\n"
    cookies = _parse_netscape_cookies(text)
    assert len(cookies) == 1

def test_parse_netscape_skip_malformed():
    """Строки с неполным числом полей должны быть пропущены."""
    text = ".host.com\tFALSE\t/\tFALSE\t0\n"  # только 5 полей вместо 7
    cookies = _parse_netscape_cookies(text)
    assert cookies == []

def test_parse_netscape_empty():
    assert _parse_netscape_cookies("") == []
    assert _parse_netscape_cookies("# только комментарии\n# ещё один\n") == []


# ──────────────────────────────────────────────
# Парсинг JSON-формата
# ──────────────────────────────────────────────

JSON_VALID = json.dumps([
    {"host": ".slack.com", "name": "d", "value": "slacktoken123abc", "path": "/", "secure": True},
    {"domain": ".github.com", "name": "user_session", "value": "ghsession456def", "path": "/",
     "expirationDate": 1893456000, "httpOnly": True},
])

def test_parse_json_basic():
    cookies = _parse_json_cookies(JSON_VALID)
    assert len(cookies) == 2

def test_parse_json_domain_normalization():
    """'domain' должен быть нормализован в 'host'."""
    cookies = _parse_json_cookies(JSON_VALID)
    github = next(c for c in cookies if c["name"] == "user_session")
    assert github["host"] == ".github.com"

def test_parse_json_expiry_normalization():
    """'expirationDate' должен быть нормализован в 'expiry'."""
    cookies = _parse_json_cookies(JSON_VALID)
    github = next(c for c in cookies if c["name"] == "user_session")
    assert github["expiry"] == 1893456000

def test_parse_json_invalid_returns_empty():
    assert _parse_json_cookies("not valid json") == []
    assert _parse_json_cookies("") == []
    assert _parse_json_cookies('{"not": "a list"}') == []

def test_parse_json_skips_items_without_name():
    data = json.dumps([{"host": ".example.com", "value": "v"}])  # нет name
    cookies = _parse_json_cookies(data)
    assert cookies == []

def test_parse_json_skips_items_without_host():
    data = json.dumps([{"name": "session", "value": "v"}])  # нет host/domain
    cookies = _parse_json_cookies(data)
    assert cookies == []


# ──────────────────────────────────────────────
# Определение redirect на страницу логина
# ──────────────────────────────────────────────

def _make_response(location: str, status_code: int = 302):
    """Создаёт мок httpx.Response с заданным заголовком Location."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = {"location": location}
    return mock_resp


def test_is_login_redirect_true_path():
    resp = _make_response("https://example.com/login")
    assert _is_login_redirect(resp) is True

def test_is_login_redirect_true_signin():
    resp = _make_response("https://app.example.com/signin?next=/dashboard")
    assert _is_login_redirect(resp) is True

def test_is_login_redirect_true_google():
    resp = _make_response("https://accounts.google.com/signin/v2")
    assert _is_login_redirect(resp) is True

def test_is_login_redirect_true_microsoft():
    resp = _make_response("https://login.microsoftonline.com/common/oauth2")
    assert _is_login_redirect(resp) is True

def test_is_login_redirect_false_dashboard():
    resp = _make_response("https://app.example.com/dashboard")
    assert _is_login_redirect(resp) is False

def test_is_login_redirect_false_empty():
    resp = _make_response("")
    assert _is_login_redirect(resp) is False


# ──────────────────────────────────────────────
# Маскирование cookie-значений
# ──────────────────────────────────────────────

def test_mask_short_value():
    assert _mask_cookie_value("short") == "***"

def test_mask_normal_value():
    result = _mask_cookie_value("abcdefghijklmnopqrstuvwxyz")
    assert result.startswith("abcd")
    assert result.endswith("wxyz")
    assert "***" in result
    # Полное значение не должно быть видно
    assert "efghijklmnopqrstuv" not in result

def test_mask_exactly_at_boundary():
    # Длина ровно 12 — граница: <= 12 → "***"
    val = "x" * 12
    assert _mask_cookie_value(val) == "***"

def test_mask_above_boundary():
    val = "x" * 13
    result = _mask_cookie_value(val)
    assert "***" in result
    assert result != "***"


# ──────────────────────────────────────────────
# Итерация cookie-файлов из ZIP
# ──────────────────────────────────────────────

def _make_zip_with_files(files: dict[str, str]) -> bytes:
    """Создаёт ZIP в памяти с заданными файлами {имя: содержимое}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_iter_cookie_files_finds_netscape(tmp_path: Path):
    netscape_content = NETSCAPE_VALID
    zip_bytes = _make_zip_with_files({"Cookies.txt": netscape_content})
    zip_path = tmp_path / "stealer.zip"
    zip_path.write_bytes(zip_bytes)

    results = list(_iter_cookie_files(zip_path))
    assert len(results) == 1
    filename, cookies = results[0]
    assert "Cookies" in filename
    assert len(cookies) == 3

def test_iter_cookie_files_finds_json_cookies(tmp_path: Path):
    zip_bytes = _make_zip_with_files({"ChromeCookies.txt": JSON_VALID})
    zip_path = tmp_path / "stealer.zip"
    zip_path.write_bytes(zip_bytes)

    results = list(_iter_cookie_files(zip_path))
    assert len(results) == 1
    _, cookies = results[0]
    assert len(cookies) == 2

def test_iter_cookie_files_skips_non_cookie_txt(tmp_path: Path):
    """Файлы без 'cookie' в имени и без Netscape-сигнатуры пропускаются."""
    zip_bytes = _make_zip_with_files({"passwords.txt": "user:pass\nuser2:pass2\n"})
    zip_path = tmp_path / "stealer.zip"
    zip_path.write_bytes(zip_bytes)

    results = list(_iter_cookie_files(zip_path))
    assert results == []

def test_iter_cookie_files_bad_zip(tmp_path: Path):
    """Битый ZIP не должен вызывать исключений — просто пустой результат."""
    zip_path = tmp_path / "bad.zip"
    zip_path.write_bytes(b"not a zip file at all")

    results = list(_iter_cookie_files(zip_path))
    assert results == []

def test_iter_cookie_files_multiple_in_zip(tmp_path: Path):
    zip_bytes = _make_zip_with_files({
        "Chrome/Cookies.txt": NETSCAPE_VALID,
        "Firefox/cookies.json": JSON_VALID,
    })
    zip_path = tmp_path / "stealer.zip"
    zip_path.write_bytes(zip_bytes)

    results = list(_iter_cookie_files(zip_path))
    assert len(results) == 2


# ──────────────────────────────────────────────
# Проверка активности сессий (с мокированием httpx)
# ──────────────────────────────────────────────

def _mock_head_response(status_code: int, location: str = ""):
    """Создаёт мок ответа httpx.Client.head()."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = MagicMock()
    mock_resp.headers.get = MagicMock(return_value=location)
    return mock_resp


def test_check_cookie_alive_200():
    mock_resp = _mock_head_response(200)
    with patch("tasks.cookie_validator.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.head = MagicMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = _check_cookie_alive("example.com", "sessionid", "abc123def456ghi")
    assert result["alive"] is True
    assert result["status_code"] == 200
    assert result["reason"] == "200_ok"


def test_check_cookie_alive_401():
    mock_resp = _mock_head_response(401)
    with patch("tasks.cookie_validator.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.head = MagicMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = _check_cookie_alive("example.com", "sessionid", "abc123def456ghi")
    assert result["alive"] is False
    assert result["reason"] == "auth_required"


def test_check_cookie_alive_redirect_to_login():
    mock_resp = _mock_head_response(302, "https://example.com/login")
    with patch("tasks.cookie_validator.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.head = MagicMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = _check_cookie_alive("example.com", "sessionid", "abc123def456ghi")
    assert result["alive"] is False
    assert result["reason"] == "login_redirect"


def test_check_cookie_alive_redirect_non_login():
    mock_resp = _mock_head_response(302, "https://example.com/dashboard")
    with patch("tasks.cookie_validator.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.head = MagicMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = _check_cookie_alive("example.com", "sessionid", "abc123def456ghi")
    assert result["alive"] is True
    assert result["reason"] == "redirect_non_login"


def test_check_cookie_alive_connection_error():
    import httpx as _httpx
    with patch("tasks.cookie_validator.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.head = MagicMock(side_effect=_httpx.ConnectError("refused"))
        mock_client_cls.return_value = mock_client

        result = _check_cookie_alive("example.com", "sessionid", "abc123def456ghi")
    assert result["alive"] is False
    assert result["status_code"] == 0
    assert result["reason"] == "connection_failed"


def test_check_cookie_alive_timeout():
    import httpx as _httpx
    with patch("tasks.cookie_validator.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.head = MagicMock(side_effect=_httpx.TimeoutException("timeout"))
        mock_client_cls.return_value = mock_client

        result = _check_cookie_alive("example.com", "sessionid", "abc123def456ghi")
    assert result["alive"] is False
    assert result["reason"] == "connection_failed"


def test_check_cookie_alive_strips_leading_dot_from_host():
    """Хосты с ведущей точкой (wildcard) должны обрабатываться корректно."""
    mock_resp = _mock_head_response(200)
    captured_urls = []

    def fake_head(url, **kwargs):
        captured_urls.append(url)
        return mock_resp

    with patch("tasks.cookie_validator.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.head = MagicMock(side_effect=fake_head)
        mock_client_cls.return_value = mock_client

        _check_cookie_alive(".example.com", "sessionid", "abc123def456ghi")

    assert captured_urls[0] == "https://example.com/"


# ──────────────────────────────────────────────
# Полная функция validate_cookies_from_zip (интеграционный тест)
# ──────────────────────────────────────────────

def test_validate_cookies_missing_file(tmp_path):
    result = validate_cookies_from_zip(
        tmp_path / "nonexistent.zip",
        "example.com",
        "http://localhost:8000",
        "secret",
    )
    assert result == {"checked": 0, "alive": 0, "dead": 0, "sent": 0}


def test_validate_cookies_alive_session_creates_critical_event(tmp_path):
    """Живая сессия должна создавать событие critical active_session_leak."""
    # Готовим ZIP с cookie-файлом для целевого домена
    netscape = (
        "# Netscape HTTP Cookie File\n"
        ".example.com\tTRUE\t/\tFALSE\t1893456000\tsessionid\tabcdefghij1234567890\n"
    )
    zip_bytes = _make_zip_with_files({"Cookies.txt": netscape})
    zip_path = tmp_path / "stealer.zip"
    zip_path.write_bytes(zip_bytes)

    # Мокируем HTTP-проверку: сессия жива
    alive_result = {"alive": True, "status_code": 200, "reason": "200_ok"}
    # Мокируем bulk_ingest: ничего не отправляем
    sent_events = []

    def fake_bulk_ingest(events, *args, **kwargs):
        sent_events.extend(events)
        return {"sent": len(events), "errors": 0}

    with patch("tasks.cookie_validator._check_cookie_alive", return_value=alive_result), \
         patch("tasks.cookie_validator.bulk_ingest", side_effect=fake_bulk_ingest):
        result = validate_cookies_from_zip(
            zip_path, "example.com", "http://localhost:8000", "secret"
        )

    assert result["checked"] == 1
    assert result["alive"] == 1
    assert result["dead"] == 0
    assert len(sent_events) == 1
    ev = sent_events[0]
    assert ev["event_type"] == "active_session_leak"
    assert ev["severity"] == "critical"
    # Значение куки должно быть замаскировано
    assert "abcdefghij1234567890" not in ev["payload"]["cookie_value_masked"]
    assert "***" in ev["payload"]["cookie_value_masked"]


def test_validate_cookies_dead_high_value_creates_medium_event(tmp_path):
    """Мёртвая ценная кука должна создавать событие medium session_leak."""
    netscape = (
        "# Netscape HTTP Cookie File\n"
        ".slack.com\tTRUE\t/\tTRUE\t1893456000\td\tslacktoken12345678901\n"
    )
    zip_bytes = _make_zip_with_files({"Cookies.txt": netscape})
    zip_path = tmp_path / "stealer.zip"
    zip_path.write_bytes(zip_bytes)

    dead_result = {"alive": False, "status_code": 302, "reason": "login_redirect"}
    sent_events = []

    def fake_bulk_ingest(events, *args, **kwargs):
        sent_events.extend(events)
        return {"sent": len(events), "errors": 0}

    with patch("tasks.cookie_validator._check_cookie_alive", return_value=dead_result), \
         patch("tasks.cookie_validator.bulk_ingest", side_effect=fake_bulk_ingest):
        # Проверяем домен "example.com" — хост .slack.com не совпадает,
        # но "d" — это ценная кука из _HIGH_VALUE_NAMES
        result = validate_cookies_from_zip(
            zip_path, "example.com", "http://localhost:8000", "secret"
        )

    assert result["checked"] == 1
    assert result["alive"] == 0
    assert result["dead"] == 1
    assert len(sent_events) == 1
    ev = sent_events[0]
    assert ev["event_type"] == "session_leak"
    assert ev["severity"] == "medium"


def test_validate_cookies_skips_low_value_unrelated_domain(tmp_path):
    """Обычные куки чужих доменов не должны создавать события."""
    netscape = (
        "# Netscape HTTP Cookie File\n"
        ".somecdn.net\tTRUE\t/\tFALSE\t0\ttracking_id\tvalue12345678901\n"
    )
    zip_bytes = _make_zip_with_files({"Cookies.txt": netscape})
    zip_path = tmp_path / "stealer.zip"
    zip_path.write_bytes(zip_bytes)

    sent_events = []

    def fake_bulk_ingest(events, *args, **kwargs):
        sent_events.extend(events)
        return {"sent": len(events), "errors": 0}

    with patch("tasks.cookie_validator.bulk_ingest", side_effect=fake_bulk_ingest):
        result = validate_cookies_from_zip(
            zip_path, "example.com", "http://localhost:8000", "secret"
        )

    assert result["checked"] == 0
    assert result["alive"] == 0
    assert len(sent_events) == 0


def test_validate_cookies_no_network_calls_on_empty_zip(tmp_path):
    """Пустой ZIP не должен делать HTTP-запросы."""
    zip_bytes = _make_zip_with_files({"readme.txt": "no cookies here"})
    zip_path = tmp_path / "stealer.zip"
    zip_path.write_bytes(zip_bytes)

    with patch("tasks.cookie_validator._check_cookie_alive") as mock_check, \
         patch("tasks.cookie_validator.bulk_ingest") as mock_ingest:
        validate_cookies_from_zip(zip_path, "example.com", "http://localhost:8000", "secret")
        mock_check.assert_not_called()
        mock_ingest.assert_not_called()


# ──────────────────────────────────────────────
# Тест эндпоинта POST /api/v1/scan/cookies
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cookie_scan_endpoint_no_files(client, superuser_token):
    """Если стилер-архивы не найдены — 404."""
    with patch("app.api.v1.endpoints.cookie_scan._find_stealer_zip", return_value=None):
        resp = await client.post(
            "/api/v1/scan/cookies",
            json={"domain": "example.com"},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
    assert resp.status_code == 404
    assert "не найдены" in resp.json()["detail"].lower() or "not found" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_cookie_scan_endpoint_triggers_scan(client, superuser_token, tmp_path):
    """При наличии ZIP — возвращает 202 и запускает задачу в фоне."""
    # Создаём фиктивный ZIP-файл
    zip_path = tmp_path / "stealer_test.zip"
    zip_bytes = _make_zip_with_files({"Cookies.txt": NETSCAPE_VALID})
    zip_path.write_bytes(zip_bytes)

    with patch("app.api.v1.endpoints.cookie_scan._find_stealer_zip", return_value=zip_path), \
         patch("app.api.v1.endpoints.cookie_scan.get_executor") as mock_executor:
        mock_exec = MagicMock()
        mock_executor.return_value = mock_exec

        resp = await client.post(
            "/api/v1/scan/cookies",
            json={"domain": "example.com"},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )

    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "processing"
    assert data["domain"] == "example.com"
    assert "stealer_test.zip" in data["stealer_file"]
    mock_exec.submit.assert_called_once()


@pytest.mark.asyncio
async def test_cookie_scan_endpoint_requires_auth(client):
    """Без токена — 401."""
    resp = await client.post(
        "/api/v1/scan/cookies",
        json={"domain": "example.com"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_cookie_scan_endpoint_empty_domain(client, superuser_token):
    """Пустой домен — 422 Unprocessable Entity."""
    resp = await client.post(
        "/api/v1/scan/cookies",
        json={"domain": ""},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_cookie_scan_endpoint_invalid_domain_chars(client, superuser_token):
    """Домен с недопустимыми символами — 422."""
    resp = await client.post(
        "/api/v1/scan/cookies",
        json={"domain": "../etc/passwd"},
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert resp.status_code == 422
