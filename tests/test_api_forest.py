"""The forest's confirmation as an admin sees it: a switch, a stored second opinion, role limits."""
import importlib

import api_core

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from conftest import ROOT, needs_model
from test_model import scan_probe

pytestmark = needs_model

PASSWORD = "correct horse battery"


@pytest.fixture
def client(tmp_path, monkeypatch):

    monkeypatch.setenv("IDS_DB", str(tmp_path / "ids.db"))
    monkeypatch.setenv("IDS_DATA_DIR", str(tmp_path / "captures"))
    monkeypatch.setenv("IDS_MODEL", str(ROOT / "bayesian_ids.pkl"))

    for name in ("IDS_ADMIN_TOKEN", "IDS_API_KEY", "IDS_SECRET_KEY", "IDS_CORS_ORIGINS"):
        monkeypatch.delenv(name, raising=False)

    monkeypatch.chdir(tmp_path)

    api = importlib.reload(importlib.import_module("api"))

    with TestClient(api.app) as client:

        client.api = api

        yield client


def test_the_model_reports_its_forest(client):

    info = client.get("/api/model").json()

    assert info["forest"] == {"available": True, "confirm": True}
    assert info["card"]["forest"]["trees"] >= 1
    assert info["card"]["test_without_forest"]["precision"] <= info["card"]["test"]["precision"]


def test_the_switch_is_remembered_and_survives_a_model_reload(client):

    assert client.put("/api/model/forest", json={"confirm": False}).json() == {"available": True, "confirm": False}

    assert client.get("/api/model").json()["forest"]["confirm"] is False

    # a retrain loads a fresh detector: the admin's choice must carry over
    client.post("/api/model/reload")

    assert client.get("/api/model").json()["forest"]["confirm"] is False

    client.put("/api/model/forest", json={"confirm": True})

    assert client.get("/api/model").json()["forest"]["confirm"] is True


def test_alerts_store_the_forests_opinion(client):

    result, records, _ = api_core.score_batch(
        pd.concat([scan_probe()] * 3, ignore_index=True), None, "api"
    )

    assert records and all(r["forest"] is not None and 0 <= r["forest"] <= 100 for r in records)

    ids = client.api.hub.store.add_alerts(records)

    stored = client.api.hub.store.get_alert(ids[0])

    assert stored["forest"] == pytest.approx(records[0]["forest"])


def test_only_admins_flip_it_and_it_is_audited(client):

    assert client.post("/api/users", json={"username": "root", "password": PASSWORD, "role": "admin"}).status_code == 200

    def sign_in(name):
        return {"Authorization": "Bearer " + client.post(
            "/api/login", json={"username": name, "password": PASSWORD}).json()["token"]}

    root = sign_in("root")

    client.post("/api/users", headers=root, json={"username": "vera", "password": PASSWORD, "role": "viewer"})

    assert client.put("/api/model/forest", json={"confirm": False}).status_code == 401
    assert client.put("/api/model/forest", headers=sign_in("vera"), json={"confirm": False}).status_code == 403
    assert client.put("/api/model/forest", headers=root, json={"confirm": False}).status_code == 200

    audit = client.get("/api/audit?limit=50", headers=root).json()

    assert any(a["action"] == "PUT /api/model/forest" for a in audit)


def test_a_model_without_a_forest_refuses_the_switch(client):

    client.api.hub.detector.forest = None
    client.api.hub.detector.use_forest = False

    response = client.put("/api/model/forest", json={"confirm": True})

    assert response.status_code == 400 and "retrain" in response.json()["detail"]
