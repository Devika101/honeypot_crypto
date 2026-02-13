"""Tests for the DeceptionNet FastAPI REST API."""

import pytest
from httpx import ASGITransport, AsyncClient

from src.api.main import app
from src.api.auth import create_access_token


@pytest.fixture
def auth_headers():
    """Create valid JWT auth headers for testing."""
    token = create_access_token(data={"sub": "admin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
class TestAuthEndpoints:
    async def test_login_success(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/token",
                json={"username": "admin", "password": "deceptionnet"},
            )
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"

    async def test_login_failure(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/token",
                json={"username": "admin", "password": "wrong"},
            )
            assert response.status_code == 401


@pytest.mark.asyncio
class TestProtectedEndpoints:
    async def test_health_check(self, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/health", headers=auth_headers)
            # Health endpoint doesn't require auth in current implementation
            assert response.status_code == 200
            assert response.json()["status"] == "healthy"

    async def test_stats_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/stats")
            assert response.status_code in (401, 403)

    async def test_stats_with_auth(self, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/stats", headers=auth_headers)
            assert response.status_code == 200
            data = response.json()
            assert "total_interactions" in data

    async def test_profiles_empty(self, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/profiles", headers=auth_headers)
            assert response.status_code == 200
            assert isinstance(response.json(), list)

    async def test_alerts_empty(self, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/alerts", headers=auth_headers)
            assert response.status_code == 200
            assert isinstance(response.json(), list)

    async def test_deploy(self, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/deploy",
                json={"use_gan": False, "use_containers": False},
                headers=auth_headers,
            )
            assert response.status_code == 200
            assert response.json()["status"] == "deployed"

    async def test_reconfigure(self, auth_headers):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/v1/reconfigure", headers=auth_headers)
            assert response.status_code == 200
