from fastapi.testclient import TestClient
from app.main import app
import pytest


@pytest.fixture
def client():
    """Create a fresh TestClient for each test."""
    with TestClient(app) as test_client:
        yield test_client


def test_read_root(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    # Verify essential fields in the enhanced root response
    assert data["service"] == "Maktabi API"
    assert data["status"] == "operational"
    assert data["version"] == "1.0.0"
    assert "timestamp" in data
    assert "documentation" in data
    assert "health_check" in data