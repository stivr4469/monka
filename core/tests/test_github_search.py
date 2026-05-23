"""Тесты GitHub Search воркера."""
import json
from unittest.mock import MagicMock, patch

# sys.path для workers добавляется в conftest.py
from tasks.github_search import SEARCH_QUERIES, _build_headers, _search_once, search_github


# ── Заголовки ─────────────────────────────────────────────────────────

def test_headers_with_token():
    headers = _build_headers("mytoken123")
    assert headers["Authorization"] == "Bearer mytoken123"
    assert "application/vnd.github" in headers["Accept"]


def test_headers_without_token():
    headers = _build_headers("")
    assert "Authorization" not in headers


# ── Количество поисковых запросов ─────────────────────────────────────

def test_search_queries_count():
    assert len(SEARCH_QUERIES) == 6


def test_search_queries_contain_domain_placeholder():
    for q in SEARCH_QUERIES:
        assert "{domain}" in q


# ── _search_once ──────────────────────────────────────────────────────

def _make_response(status_code: int, body: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    return resp


def test_search_once_success():
    items = [{"repository": {"full_name": "user/repo"}, "path": "config.env", "html_url": "https://github.com/..."}]
    with patch("httpx.get", return_value=_make_response(200, {"items": items})):
        result = _search_once("example.com password", {})
    assert result == items


def test_search_once_empty():
    with patch("httpx.get", return_value=_make_response(200, {"items": []})):
        result = _search_once("example.com password", {})
    assert result == []


def test_search_once_non_200():
    with patch("httpx.get", return_value=_make_response(422, {})):
        result = _search_once("example.com password", {})
    assert result == []


def test_search_once_network_error():
    with patch("httpx.get", side_effect=Exception("connection refused")):
        result = _search_once("example.com password", {})
    assert result == []


def test_search_once_rate_limit_then_success():
    items = [{"repository": {"full_name": "user/repo2"}, "path": "a.env", "html_url": "https://..."}]
    responses = iter([
        _make_response(403, {}),
        _make_response(200, {"items": items}),
    ])
    with patch("httpx.get", side_effect=lambda *a, **kw: next(responses)):
        with patch("time.sleep"):
            result = _search_once("example.com token", {})
    assert result == items


# ── search_github (интеграционный, всё замокано) ───────────────────────

def _mock_ingest_ok(*args, **kwargs):
    resp = MagicMock()
    resp.json.return_value = {"status": "accepted"}
    return resp


def _mock_ingest_dup(*args, **kwargs):
    resp = MagicMock()
    resp.json.return_value = {"status": "duplicate"}
    return resp


def test_search_github_sends_events():
    one_item = [{"repository": {"full_name": "u/r", "html_url": "https://github.com/u/r"}, "path": "x.env", "html_url": "https://github.com/u/r/blob/main/x.env"}]

    with patch("tasks.github_search._search_once", return_value=one_item), \
         patch("httpx.post", side_effect=_mock_ingest_ok), \
         patch("time.sleep"):
        result = search_github("example.com", "token", "http://localhost:8000", "secret")

    assert result["queries"] == 6
    assert result["found"] == 6  # 1 item × 6 queries
    assert result["sent"] == 6
    assert result["errors"] == 0


def test_search_github_no_results():
    with patch("tasks.github_search._search_once", return_value=[]), \
         patch("time.sleep"):
        result = search_github("clean-domain.com", "token", "http://localhost:8000", "secret")

    assert result["found"] == 0
    assert result["sent"] == 0
    assert result["errors"] == 0


def test_search_github_ingest_error():
    one_item = [{"repository": {"full_name": "u/r", "html_url": ""}, "path": "a.env", "html_url": ""}]

    with patch("tasks.github_search._search_once", return_value=one_item), \
         patch("httpx.post", side_effect=Exception("network error")), \
         patch("time.sleep"):
        result = search_github("example.com", "token", "http://localhost:8000", "secret")

    assert result["errors"] == 6  # все 6 запросов упали
