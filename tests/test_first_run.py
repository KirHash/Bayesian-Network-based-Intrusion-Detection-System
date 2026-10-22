"""
A brand-new install, driven only through the dashboard's API: the server
starts with no model and no data, training data is uploaded, the model is
trained, and traffic is scored. No terminal step in between.
"""
import importlib

import pytest
from fastapi.testclient import TestClient

from conftest import write_pcap
from test_api_operations import synthetic_dataset, wait_for

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def client(tmp_path_factory):

    mp = pytest.MonkeyPatch()

    base = tmp_path_factory.mktemp("fresh")

    (base / "captures").mkdir()

    mp.setenv("IDS_DB", str(base / "ids.db"))
    mp.setenv("IDS_MODEL", str(base / "no-model-here.pkl"))
    mp.setenv("IDS_DATA_DIR", str(base / "captures"))
    mp.setenv("IDS_DATASET_DIR", str(base / "dataset"))

    for name in ("IDS_ADMIN_TOKEN", "IDS_API_KEY"):
        mp.delenv(name, raising=False)

    mp.chdir(base)

    api = importlib.reload(importlib.import_module("api"))

    with TestClient(api.app) as client:

        client.api = api
        client.base = base

        yield client

    mp.undo()


def test_the_server_starts_without_a_model_and_says_so(client):

    health = client.get("/api/healthz")

    assert health.status_code == 503
    assert health.json()["status"] == "degraded" and health.json()["model"] is False

    model = client.get("/api/model").json()

    assert model["trained"] is False
    assert "Retrain" in model["message"]
    assert model["classes"] == [] and model["dataset_files"] == 0

    # the rest of the dashboard still works
    assert client.get("/api/stats").status_code == 200
    assert client.get("/api/alerts").json() == []
    assert client.get("/api/server").status_code == 200

    assert any("no usable model" in l["message"] for l in client.get("/api/logs").json())


def test_nothing_can_be_scored_until_there_is_a_model(client):

    write_pcap(client.base / "captures" / "web.pcap", flows=2)

    start = client.post("/api/capture/start", json={"mode": "pcap", "target": "web.pcap"})

    assert start.status_code == 503 and "Retrain" in start.json()["detail"]

    assert client.post("/api/score", json=[{"Destination Port": 80}]).status_code == 503

    assert client.post("/api/replay", json={"running": True}).status_code == 503


def test_training_needs_data_and_the_dashboard_says_where_to_get_it(client):

    refused = client.post("/api/jobs", json={"kind": "train"})

    assert refused.status_code == 400 and "Upload" in refused.json()["detail"]


def test_upload_train_and_score_with_no_terminal(client):

    synthetic_dataset(client.base / "sample.csv", rows=2000)

    uploaded = client.put(
        "/api/files/dataset/sample.csv", content=(client.base / "sample.csv").read_bytes()
    )

    assert uploaded.status_code == 200, uploaded.text

    assert wait_for(lambda: client.get("/api/files").json()["dataset"][0]["labels"], 60)

    assert client.get("/api/model").json()["dataset_files"] == 1

    job_id = client.post("/api/jobs", json={"kind": "train"}).json()["id"]

    job = wait_for(
        lambda: (j := client.get(f"/api/jobs/{job_id}").json())["state"] != "running" and j, 240
    )

    assert job["state"] == "succeeded", "\n".join(job["output"][-15:])

    # the running server picked the new model up by itself
    assert client.get("/api/healthz").json() == {
        **client.get("/api/healthz").json(), "status": "ok", "model": True
    }

    model = client.get("/api/model").json()

    assert model["trained"] is True and set(model["classes"]) == {"BENIGN", "DDoS"}
    assert model["card"]["test"]["recall"] > 0.9

    # and it scores: DDoS-like flows from the same generator are flagged
    import pandas as pd

    flows = pd.read_csv(client.base / "sample.csv", encoding="latin-1")

    ddos = flows[flows["Label"] == "DDoS"].drop(columns="Label").head(50)

    scored = client.post("/api/score", json=ddos.to_dict("records"))

    assert scored.status_code == 200

    assert len(scored.json()["alerts"]) > 40


def test_capture_works_once_the_model_exists(client):

    assert client.post("/api/capture/start", json={"mode": "pcap", "target": "web.pcap"}).status_code == 200

    assert wait_for(lambda: client.get("/api/capture").json()["state"] == "finished", 30)

    assert client.get("/api/capture").json()["flows"] == 2
