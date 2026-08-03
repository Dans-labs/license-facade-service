import os

import pytest
from fastapi.testclient import TestClient

from src.license_facade_service.main import create_app


@pytest.mark.integration
def test_optional_fuseki_profile():
    if os.getenv("RUN_FUSEKI_INTEGRATION") != "1":
        pytest.skip("Set RUN_FUSEKI_INTEGRATION=1 to run Fuseki integration profile")
    client = TestClient(create_app())
    response = client.get("/api/v1/health")
    assert response.status_code == 200

