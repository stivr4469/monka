"""Тесты Technology Profiling — POST /api/v1/scan/tech-profile (задача 10.A)."""
from unittest.mock import patch, MagicMock

import pytest
from httpx import AsyncClient

TECH_SCAN_URL = "/api/v1/scan/tech-profile"

# Путь к функции воркера в контексте эндпоинта (именно там делается import)
_WORKER_PATH = "app.api.v1.endpoints.tech_scan.run_tech_profiler"

# Базовый mock-результат воркера
_BASE_RESULT = {
    "domain": "example.com",
    "technologies": [
        {"name": "Nginx", "version": "1.24", "category": "web-server"},
    ],
    "eol_detected": [],
    "severity": "info",
    "scanned_at": "2026-05-25T12:00:00Z",
}


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ─── Тесты ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tech_scan_accepted(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """POST с валидным доменом возвращает 200 с полями status и domain."""
    mock_result = dict(_BASE_RESULT)

    with patch(_WORKER_PATH, return_value=mock_result):
        resp = await client.post(
            TECH_SCAN_URL,
            json={"domain": "example.com"},
            headers=_auth_headers(superuser_token),
        )

    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "domain" in data
    assert data["domain"] == "example.com"


@pytest.mark.asyncio
async def test_tech_scan_returns_technologies(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Воркер возвращает список технологий — в ответе technologies не пустой."""
    mock_result = {
        **_BASE_RESULT,
        "technologies": [
            {"name": "Nginx", "version": "1.24"},
            {"name": "React", "version": "18.2"},
        ],
    }

    with patch(_WORKER_PATH, return_value=mock_result):
        resp = await client.post(
            TECH_SCAN_URL,
            json={"domain": "example.com"},
            headers=_auth_headers(superuser_token),
        )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["technologies"]) > 0
    names = [t["name"] for t in data["technologies"]]
    assert "Nginx" in names


@pytest.mark.asyncio
async def test_tech_scan_eol_detected(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Воркер обнаруживает EOL-технологии — в ответе eol_detected не пустой."""
    mock_result = {
        **_BASE_RESULT,
        "technologies": [{"name": "PHP", "version": "7.4"}],
        "eol_detected": [
            {"tech": "PHP", "version": "7.4", "eol_date": "2022-11-28"},
        ],
        "severity": "medium",
    }

    with patch(_WORKER_PATH, return_value=mock_result):
        resp = await client.post(
            TECH_SCAN_URL,
            json={"domain": "example.com"},
            headers=_auth_headers(superuser_token),
        )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["eol_detected"]) > 0
    eol_item = data["eol_detected"][0]
    assert eol_item["tech"] == "PHP"


@pytest.mark.asyncio
async def test_tech_scan_invalid_domain_empty(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Пустой домен → 422 (ошибка валидации)."""
    resp = await client.post(
        TECH_SCAN_URL,
        json={"domain": ""},
        headers=_auth_headers(superuser_token),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_tech_scan_invalid_domain_injection(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Домен со слешами (path-injection) → 422 (ошибка валидации)."""
    resp = await client.post(
        TECH_SCAN_URL,
        json={"domain": "evil/../etc"},
        headers=_auth_headers(superuser_token),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_tech_scan_requires_auth(client: AsyncClient) -> None:
    """Запрос без токена → 401."""
    resp = await client.post(
        TECH_SCAN_URL,
        json={"domain": "example.com"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_tech_scan_rate_limit_headers_present(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Успешный запрос возвращает 200; rate-limiting не блокирует первый вызов."""
    mock_result = dict(_BASE_RESULT)

    # DNS мокируем: тестовая среда не резолвит внешние домены → нужен публичный IP
    with patch("app.core.ssrf.socket.gethostbyname", return_value="93.184.216.34"):
        with patch(_WORKER_PATH, return_value=mock_result):
            resp = await client.post(
                TECH_SCAN_URL,
                json={"domain": "ratelimit-check.com"},
                headers=_auth_headers(superuser_token),
            )

    # Первый запрос в тесте никогда не должен блокироваться rate limiter'ом
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_tech_scan_ssrf_loopback_blocked(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Домен, резолвящийся в loopback IP → 400 (SSRF-защита)."""
    # Домен с корректным форматом, но DNS резолвится во внутренний адрес
    with patch("app.core.ssrf.socket.gethostbyname", return_value="127.0.0.1"):
        resp = await client.post(
            TECH_SCAN_URL,
            json={"domain": "internal.example.com"},
            headers=_auth_headers(superuser_token),
        )

    assert resp.status_code == 400
    assert "SSRF" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_tech_scan_ssrf_private_ip_blocked(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Домен, резолвящийся в RFC 1918 адрес → 400 (SSRF-защита)."""
    with patch("app.core.ssrf.socket.gethostbyname", return_value="192.168.1.100"):
        resp = await client.post(
            TECH_SCAN_URL,
            json={"domain": "private.example.com"},
            headers=_auth_headers(superuser_token),
        )

    assert resp.status_code == 400
    assert "SSRF" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_tech_scan_ssrf_public_ip_allowed(
    client: AsyncClient,
    superuser_token: str,
) -> None:
    """Домен, резолвящийся в публичный IP → не блокируется SSRF-защитой."""
    mock_result = dict(_BASE_RESULT)

    with patch("app.core.ssrf.socket.gethostbyname", return_value="93.184.216.34"):
        with patch(_WORKER_PATH, return_value=mock_result):
            resp = await client.post(
                TECH_SCAN_URL,
                json={"domain": "example.com"},
                headers=_auth_headers(superuser_token),
            )

    assert resp.status_code == 200
