"""The API answers browsers on a separate site (Netlify) only when told to, and only those sites."""
import importlib

import pytest
from fastapi.testclient import TestClient

from conftest import needs_model

pytestmark = needs_model

SITE = "https://ids-demo.netlify.app"


@pytest.fixture(scope="module")
def client(tmp_path_factory):

    mp = pytest.MonkeyPatch()

    base = tmp_path_factory.mktemp("cors")

    mp.setenv("IDS_DB", str(base / "ids.db"))
    mp.setenv("IDS_DATA_DIR", str(base / "captures"))
    mp.setenv("IDS_CORS_ORIGINS", f"{SITE}/, *, http://bad origin, https://other.example:8443")

    for name in ("IDS_ADMIN_TOKEN", "IDS_API_KEY", "IDS_SECRET_KEY"):
        mp.delenv(name, raising=False)

    mp.chdir(base)

    api = importlib.reload(importlib.import_module("api"))

    with TestClient(api.app) as client:

        client.api = api

        yield client

    mp.delenv("IDS_CORS_ORIGINS")

    importlib.reload(api)

    mp.undo()


def test_only_well_formed_origins_are_kept(client):

    assert client.api.cors_origins() == [SITE, "https://other.example:8443"]


def test_preflight_from_an_allowed_site_is_answered_without_signing_in(client):

    # accounts exist, so a request without a token is refused ...
    client.post("/api/users", json={"username": "root", "password": "correct horse battery", "role": "admin"})

    assert client.get("/api/stats").status_code == 401

    # ... but the browser's permission check carries no token and must still succeed
    response = client.options("/api/stats", headers={
        "Origin": SITE, "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
    })

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == SITE
    assert "authorization" in response.headers["access-control-allow-headers"].lower()
    assert "access-control-allow-credentials" not in response.headers


def test_other_sites_get_no_permission(client):

    response = client.options("/api/stats", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "GET",
    })

    assert "access-control-allow-origin" not in response.headers
    assert response.status_code == 400


def test_real_responses_carry_the_header_for_the_allowed_site_only(client):

    login = client.post("/api/login", headers={"Origin": SITE},
                        json={"username": "root", "password": "correct horse battery"})

    assert login.status_code == 200
    assert login.headers["access-control-allow-origin"] == SITE

    evil = client.post("/api/login", headers={"Origin": "https://evil.example"},
                       json={"username": "root", "password": "correct horse battery"})

    assert "access-control-allow-origin" not in evil.headers
