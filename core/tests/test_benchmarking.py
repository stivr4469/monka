"""Тесты Industry Benchmarking (задача 13.F): сервис и endpoint."""
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.organization import Organization, OrgPlan
from app.models.user import User
from app.services.benchmarking import (
    INDUSTRY_BENCHMARKS,
    _calc_percentile,
    _normalize_industry,
    _score_to_rank,
    compare_with_benchmark,
    get_industry_benchmark,
)

# Пароль для тестовых пользователей (совпадает с conftest.py)
TEST_PASSWORD = "testpassword"
BENCHMARK_URL = "/api/v1/dashboard/benchmark"


# ─── Фикстуры ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def org_fintech(db_session: AsyncSession) -> Organization:
    """Финтех-организация."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=f"Fintech Org {uid}",
        slug=f"fintech-org-{uid}",
        plan=OrgPlan.professional.value,
        industry="fintech",
    )
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    return org


@pytest_asyncio.fixture
async def user_with_fintech_org(
    db_session: AsyncSession,
    org_fintech: Organization,
) -> User:
    """Пользователь привязанный к fintech-организации."""
    email = f"fintech_user_{uuid.uuid4().hex[:8]}@test.com"
    user = User(
        email=email,
        hashed_password=hash_password(TEST_PASSWORD),
        is_superuser=False,
        organization_id=org_fintech.id,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def fintech_user_token(
    client: AsyncClient,
    user_with_fintech_org: User,
) -> str:
    """JWT-токен для fintech-пользователя."""
    resp = await client.post(
        "/api/v1/auth/token",
        data={"username": user_with_fintech_org.email, "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


# ─── Тесты сервисных функций ──────────────────────────────────────────────────

class TestNormalizeIndustry:
    """Тесты нормализации названия отрасли."""

    def test_known_industry_returned_as_is(self):
        assert _normalize_industry("fintech") == "fintech"

    def test_uppercase_normalized(self):
        assert _normalize_industry("FINTECH") == "fintech"

    def test_unknown_industry_maps_to_other(self):
        assert _normalize_industry("aerospace") == "other"

    def test_none_maps_to_other(self):
        assert _normalize_industry(None) == "other"

    def test_empty_string_maps_to_other(self):
        assert _normalize_industry("") == "other"

    def test_all_valid_industries_accepted(self):
        for industry in INDUSTRY_BENCHMARKS:
            assert _normalize_industry(industry) == industry


class TestCalcPercentile:
    """Тесты расчёта перцентиля."""

    def test_at_p50_returns_50(self):
        result = _calc_percentile(72.0, p25=60.0, p50=72.0, p75=82.0)
        assert result == 50

    def test_at_p25_returns_25(self):
        result = _calc_percentile(60.0, p25=60.0, p50=72.0, p75=82.0)
        assert result == 25

    def test_at_p75_returns_75(self):
        result = _calc_percentile(82.0, p25=60.0, p50=72.0, p75=82.0)
        assert result == 75

    def test_below_p25_low_percentile(self):
        result = _calc_percentile(30.0, p25=60.0, p50=72.0, p75=82.0)
        assert result < 25

    def test_above_p75_high_percentile(self):
        result = _calc_percentile(95.0, p25=60.0, p50=72.0, p75=82.0)
        assert result > 75


class TestScoreToRank:
    """Тесты определения rank по score."""

    def test_below_p25_is_below_average(self):
        assert _score_to_rank(50.0, p25=60.0, p50=72.0, p75=82.0) == "below_average"

    def test_at_p25_is_average(self):
        assert _score_to_rank(60.0, p25=60.0, p50=72.0, p75=82.0) == "average"

    def test_between_p25_p50_is_average(self):
        assert _score_to_rank(66.0, p25=60.0, p50=72.0, p75=82.0) == "average"

    def test_at_p50_is_above_average(self):
        assert _score_to_rank(72.0, p25=60.0, p50=72.0, p75=82.0) == "above_average"

    def test_between_p50_p75_is_above_average(self):
        assert _score_to_rank(77.0, p25=60.0, p50=72.0, p75=82.0) == "above_average"

    def test_at_p75_is_top_quartile(self):
        assert _score_to_rank(82.0, p25=60.0, p50=72.0, p75=82.0) == "top_quartile"

    def test_above_p75_is_top_quartile(self):
        assert _score_to_rank(95.0, p25=60.0, p50=72.0, p75=82.0) == "top_quartile"


# ─── Тесты get_industry_benchmark ─────────────────────────────────────────────

class TestGetIndustryBenchmark:
    """Тесты получения бенчмарка отрасли."""

    @pytest.mark.asyncio
    async def test_benchmark_returns_industry_data(self):
        """get_industry_benchmark возвращает структуру с обязательными полями."""
        mock_db = AsyncMock()
        # Мокаем: нет организаций в БД → fallback на статику
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        result = await get_industry_benchmark("fintech", mock_db)

        assert "avg_score" in result
        assert "p25" in result
        assert "p50" in result
        assert "p75" in result
        assert result["avg_score"] == 72.0
        assert result["p25"] == 60.0
        assert result["p50"] == 72.0
        assert result["p75"] == 82.0

    @pytest.mark.asyncio
    async def test_benchmark_fallback_when_no_industry_data(self):
        """industry='unknown' использует 'other' как fallback."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        result = await get_industry_benchmark("unknown_industry_xyz", mock_db)

        # Должны получить данные для "other"
        assert result["avg_score"] == INDUSTRY_BENCHMARKS["other"]["avg_score"]
        assert result["p50"] == INDUSTRY_BENCHMARKS["other"]["p50"]

    @pytest.mark.asyncio
    async def test_benchmark_contains_category_data(self):
        """Бенчмарк содержит средние значения по категориям."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        result = await get_industry_benchmark("healthcare", mock_db)

        assert "network_security" in result
        assert "dns_health" in result
        assert "application_security" in result
        assert "credential_exposure" in result
        assert "dark_web_presence" in result
        assert "brand_safety" in result

    @pytest.mark.asyncio
    async def test_benchmark_all_industries_available(self):
        """Все отрасли из INDUSTRY_BENCHMARKS доступны."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        for industry in INDUSTRY_BENCHMARKS:
            result = await get_industry_benchmark(industry, mock_db)
            assert result["avg_score"] == INDUSTRY_BENCHMARKS[industry]["avg_score"]


# ─── Тесты compare_with_benchmark ────────────────────────────────────────────

class TestCompareWithBenchmark:
    """Тесты сравнения score организации с бенчмарком."""

    # Типичные score по категориям для fintech
    _CAT_SCORES_AVG = {
        "network_security": 75.0,
        "dns_health": 78.0,
        "application_security": 70.0,
        "credential_exposure": 65.0,
        "dark_web_presence": 68.0,
        "brand_safety": 80.0,
    }

    @pytest.mark.asyncio
    async def test_compare_above_average(self):
        """Score выше p50 → rank='above_average'."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        # fintech p50=72.0, p75=82.0 → 74.5 попадает в above_average
        result = await compare_with_benchmark(
            org_score=74.5,
            org_category_scores=self._CAT_SCORES_AVG,
            industry="fintech",
            db=mock_db,
        )

        assert result["rank"] == "above_average"
        assert result["percentile"] > 50
        assert result["industry"] == "fintech"

    @pytest.mark.asyncio
    async def test_compare_below_average(self):
        """Score ниже p25 → rank='below_average'."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        # fintech p25=60.0 → 45.0 это below_average
        result = await compare_with_benchmark(
            org_score=45.0,
            org_category_scores=self._CAT_SCORES_AVG,
            industry="fintech",
            db=mock_db,
        )

        assert result["rank"] == "below_average"
        assert result["percentile"] < 25

    @pytest.mark.asyncio
    async def test_compare_top_quartile(self):
        """Score выше p75 → rank='top_quartile'."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        # fintech p75=82.0 → 90.0 это top_quartile
        result = await compare_with_benchmark(
            org_score=90.0,
            org_category_scores=self._CAT_SCORES_AVG,
            industry="fintech",
            db=mock_db,
        )

        assert result["rank"] == "top_quartile"
        assert result["percentile"] > 75

    @pytest.mark.asyncio
    async def test_category_comparison_delta(self):
        """delta = your - avg: положительная когда выше среднего."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        # fintech network_security avg=75.0, наш score=80.0 → delta=+5.0
        cat_scores = dict(self._CAT_SCORES_AVG)
        cat_scores["network_security"] = 80.0

        result = await compare_with_benchmark(
            org_score=74.5,
            org_category_scores=cat_scores,
            industry="fintech",
            db=mock_db,
        )

        net_sec = result["category_comparison"]["network_security"]
        assert net_sec["your"] == 80.0
        assert net_sec["avg"] == 75.0
        assert net_sec["delta"] == 5.0

    @pytest.mark.asyncio
    async def test_category_comparison_negative_delta(self):
        """delta отрицательная когда ниже среднего."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        # fintech credential_exposure avg=65.0, наш score=50.0 → delta=-15.0
        cat_scores = dict(self._CAT_SCORES_AVG)
        cat_scores["credential_exposure"] = 50.0

        result = await compare_with_benchmark(
            org_score=65.0,
            org_category_scores=cat_scores,
            industry="fintech",
            db=mock_db,
        )

        cred = result["category_comparison"]["credential_exposure"]
        assert cred["your"] == 50.0
        assert cred["delta"] < 0

    @pytest.mark.asyncio
    async def test_compare_returns_all_required_fields(self):
        """Ответ содержит все обязательные поля."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        result = await compare_with_benchmark(
            org_score=72.0,
            org_category_scores=self._CAT_SCORES_AVG,
            industry="saas",
            db=mock_db,
        )

        assert "industry" in result
        assert "your_score" in result
        assert "benchmark" in result
        assert "percentile" in result
        assert "rank" in result
        assert "category_comparison" in result
        assert "avg" in result["benchmark"]
        assert "p25" in result["benchmark"]
        assert "p50" in result["benchmark"]
        assert "p75" in result["benchmark"]

    @pytest.mark.asyncio
    async def test_compare_average_rank(self):
        """Score между p25 и p50 → rank='average'."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        # fintech p25=60.0, p50=72.0 → 66.0 это average
        result = await compare_with_benchmark(
            org_score=66.0,
            org_category_scores=self._CAT_SCORES_AVG,
            industry="fintech",
            db=mock_db,
        )

        assert result["rank"] == "average"


# ─── Тесты endpoint /dashboard/benchmark ─────────────────────────────────────

class TestBenchmarkEndpoint:
    """Интеграционные тесты endpoint GET /api/v1/dashboard/benchmark."""

    @pytest.mark.asyncio
    async def test_benchmark_endpoint_returns_200(
        self,
        client: AsyncClient,
        fintech_user_token: str,
    ):
        """Endpoint возвращает 200 с валидной структурой."""
        resp = await client.get(
            BENCHMARK_URL,
            headers={"Authorization": f"Bearer {fintech_user_token}"},
        )
        assert resp.status_code == 200

        data = resp.json()
        assert "industry" in data
        assert "comparison" in data
        assert "peer_count" in data

    @pytest.mark.asyncio
    async def test_benchmark_endpoint_requires_auth(self, client: AsyncClient):
        """Endpoint требует авторизации."""
        resp = await client.get(BENCHMARK_URL)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_benchmark_endpoint_returns_industry_fintech(
        self,
        client: AsyncClient,
        fintech_user_token: str,
    ):
        """Endpoint возвращает правильную отрасль для fintech-организации."""
        resp = await client.get(
            BENCHMARK_URL,
            headers={"Authorization": f"Bearer {fintech_user_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["industry"] == "fintech"

    @pytest.mark.asyncio
    async def test_benchmark_comparison_has_rank(
        self,
        client: AsyncClient,
        fintech_user_token: str,
    ):
        """Comparison содержит rank."""
        resp = await client.get(
            BENCHMARK_URL,
            headers={"Authorization": f"Bearer {fintech_user_token}"},
        )
        assert resp.status_code == 200
        comparison = resp.json()["comparison"]
        assert comparison["rank"] in (
            "below_average", "average", "above_average", "top_quartile"
        )

    @pytest.mark.asyncio
    async def test_benchmark_comparison_has_percentile(
        self,
        client: AsyncClient,
        fintech_user_token: str,
    ):
        """Comparison содержит percentile в диапазоне 0–100."""
        resp = await client.get(
            BENCHMARK_URL,
            headers={"Authorization": f"Bearer {fintech_user_token}"},
        )
        assert resp.status_code == 200
        comparison = resp.json()["comparison"]
        assert 0 <= comparison["percentile"] <= 100

    @pytest.mark.asyncio
    async def test_benchmark_comparison_has_category_comparison(
        self,
        client: AsyncClient,
        fintech_user_token: str,
    ):
        """Comparison содержит категорийное сравнение для всех 6 категорий."""
        resp = await client.get(
            BENCHMARK_URL,
            headers={"Authorization": f"Bearer {fintech_user_token}"},
        )
        assert resp.status_code == 200
        cat_comp = resp.json()["comparison"]["category_comparison"]
        expected_cats = {
            "network_security",
            "dns_health",
            "application_security",
            "credential_exposure",
            "dark_web_presence",
            "brand_safety",
        }
        assert expected_cats == set(cat_comp.keys())

    @pytest.mark.asyncio
    async def test_benchmark_fallback_when_no_industry_set(
        self,
        client: AsyncClient,
        superuser_token: str,
    ):
        """Суперпользователь без org получает бенчмарк с industry='other'."""
        resp = await client.get(
            BENCHMARK_URL,
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Суперпользователь без org → industry='other'
        assert data["industry"] == "other"
