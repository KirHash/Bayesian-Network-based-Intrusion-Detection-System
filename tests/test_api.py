"""
End-to-end API test: starts the real app (loads the model and dataset,
about a minute), replays demo traffic and exercises everything that
touches the database, the notifier and the websocket.
"""
import importlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from conftest import needs_dataset, needs_model, pcap_to_csv, write_pcap

pytestmark = [pytest.mark.slow, needs_model, needs_dataset]

KEY = "test-key"


@pytest.fixture(scope="module")
def webhook():

    received = []

    class Handler(BaseHTTPRequestHandler):

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append(json.loads(body))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)

    threading.Thread(target=server.serve_forever, daemon=True).start()

    yield f"http://127.0.0.1:{server.server_port}/hook", received

    server.shutdown()


@pytest.fixture(scope="module")
def client(tmp_path_factory, webhook):

    mp = pytest.MonkeyPatch()

    mp.setenv("IDS_DB", str(tmp_path_factory.mktemp("db") / "ids.db"))
    mp.setenv("IDS_API_KEY", KEY)

    captures = tmp_path_factory.mktemp("captures")

    write_pcap(captures / "web.pcap", flows=4)
    pcap_to_csv(captures / "web.pcap", captures / "flows.csv")

    mp.setenv("IDS_DATA_DIR", str(captures))

    api = importlib.reload(importlib.import_module("api"))

    with TestClient(api.app) as client:

        # deliver every risk level from every source, quickly
        api.hub.notifier.config.update({
            "min_risk": "Medium",
            "sources": ["capture", "api", "replay"],
            "window_seconds": 1,
            "webhook": {"url": webhook[0], "format": "slack"}
        })

        client.api = api

        # about 600 demo flows, then stop
        client.post("/api/replay", json={"running": True, "rate": 300})
        time.sleep(3.5)
        client.post("/api/replay", json={"running": False})
        time.sleep(1.5)

        yield client

    mp.undo()


def test_model_info(client):

    info = client.get("/api/model").json()

    assert "BENIGN" in info["classes"] and info["features"] == 20


def test_replay_traffic_is_persisted_and_counted(client):

    stats = client.get("/api/stats?source=replay").json()

    assert stats["total"] >= 600
    assert stats["alerts"] > 50
    assert sum(stats["by_status"].values()) == stats["alerts"]
    # accuracy against the replay's known labels
    assert stats["precision"] > 0.9 and stats["recall"] > 0.9


def test_alert_list_filters_and_detail(client):

    alerts = client.get("/api/alerts?limit=20").json()

    assert alerts and all(a["status"] in ("new", "investigating") for a in alerts)

    ids = [a["id"] for a in alerts]

    assert ids == sorted(ids, reverse=True)

    detail = client.get(f"/api/alerts/{ids[0]}").json()

    assert detail["posterior"] and detail["features"] and detail["events"] == []

    only = client.get("/api/alerts?risk=Critical&limit=500").json()

    assert all(a["risk"] == "Critical" for a in only)

    assert client.get("/api/alerts/99999999").status_code == 404


def test_handling_workflow(client):

    alert_id = client.get("/api/alerts?limit=1").json()[0]["id"]

    updated = client.patch(f"/api/alerts/{alert_id}", json={
        "status": "investigating", "assignee": "sam", "note": "checking",
        "actor": "tester"
    }).json()

    assert updated["status"] == "investigating"
    assert [e["actor"] for e in updated["events"]] == ["tester"] * 3

    assert client.patch(
        f"/api/alerts/{alert_id}", json={"status": "bogus"}
    ).status_code == 400

    assert client.patch(
        "/api/alerts/99999999", json={"status": "resolved"}
    ).status_code == 404

    others = [a["id"] for a in client.get("/api/alerts?limit=4").json()
              if a["id"] != alert_id][:2]

    assert client.post("/api/alerts/bulk", json={
        "ids": others, "status": "false_positive"
    }).json() == {"changed": len(others)}

    closed = client.get("/api/alerts?status=false_positive&limit=500").json()

    assert set(others) <= {a["id"] for a in closed}

    open_ids = {a["id"] for a in client.get("/api/alerts?limit=500").json()}

    assert not set(others) & open_ids and alert_id in open_ids

    assert any(
        a["id"] == alert_id
        for a in client.get("/api/alerts?q=checking&status=all").json()
    )


def test_notification_digest_reaches_the_webhook(client, webhook):

    _, received = webhook

    deadline = time.time() + 6

    while not received and time.time() < deadline:
        time.sleep(0.5)

    assert received, "no digest arrived"

    assert "new alert(s)" in received[0]["text"]

    # a flood is summarised, not sent alert by alert
    assert len(received) < 10

    status = client.get("/api/notifications").json()

    assert status["channels"] == ["webhook"]
    assert status["recent"][0]["ok"] == 1

    assert client.post("/api/notifications/test").json() == {
        "webhook": {"ok": True}
    }


def test_recent_flows_include_benign_ones(client):

    flows = client.get("/api/flows?source=replay&limit=500").json()

    assert len(flows) > 100

    verdicts = {f["prediction"] for f in flows}

    assert verdicts == {"ATTACK", "BENIGN"}

    only_benign = client.get("/api/flows?source=replay&verdict=benign").json()

    assert only_benign and all(f["prediction"] == "BENIGN" for f in only_benign)

    # attacks link to their stored alert, benign flows have none
    linked = [f for f in flows if f["prediction"] == "ATTACK"]

    assert all(f["alert_id"] for f in linked)
    assert all(f["alert_id"] is None for f in flows if f["prediction"] == "BENIGN")

    assert client.get("/api/flows?source=capture").json() == []


def test_sources_report_activity(client):

    sources = client.get("/api/sources").json()

    assert set(sources) == {"capture", "api", "replay"}

    assert sources["replay"]["flows"] >= 600
    assert sources["replay"]["seconds_since_last"] is not None
    assert sources["capture"]["seconds_since_last"] is None


def test_drift_is_reported_per_source(client):

    drift = client.get("/api/drift").json()

    assert "replay" in drift
    assert drift["replay"]["status"] in {"stable", "warning", "drift", "warming up"}


def test_score_endpoint_needs_the_key_and_valid_input(client):

    flows = client.api.hub.replay_pool.drop(columns="Label").head(3)

    rows = flows.to_dict("records")

    assert client.post("/api/score", json=rows).status_code == 401

    headers = {"X-API-Key": KEY}

    good = client.post("/api/score", json=rows, headers=headers)

    assert good.status_code == 200 and good.json()["scored"] == 3

    assert client.post(
        "/api/score?source=replay", json=rows, headers=headers
    ).status_code == 400

    assert client.post("/api/score", json=[], headers=headers).status_code == 400

    assert client.post(
        "/api/score", json=[{"x": 1}], headers=headers
    ).status_code == 400

    too_many = rows * 2000

    assert client.post(
        "/api/score", json=too_many, headers=headers
    ).status_code == 413


def test_captured_flows_keep_their_addresses(client):

    flows = client.api.hub.replay_pool.drop(columns="Label")

    flows = flows[flows["Destination Port"] == 22].head(20)

    result = client.post(
        "/api/score?source=capture",
        json=flows.to_dict("records"),
        headers={"X-API-Key": KEY}
    ).json()

    assert result["scored"] == len(flows)

    for alert in result["alerts"]:
        assert alert["source"] == "capture" and alert["src_ip"]


def test_clearing_the_demo_keeps_real_alerts(client):

    before = client.get("/api/stats?source=capture").json()["total"]

    assert client.post("/api/reset").json() == {"ok": True}

    assert client.get("/api/stats?source=replay").json()["total"] == 0
    assert client.get("/api/stats?source=capture").json()["total"] == before


def test_notification_config_can_be_reloaded(client, tmp_path, monkeypatch):

    notifier = client.api.hub.notifier

    before = dict(notifier.config)

    path = tmp_path / "notify.json"

    path.write_text(json.dumps({
        "min_risk": "Critical",
        "webhook": {"url": "http://127.0.0.1:9/none", "format": "discord"}
    }))

    monkeypatch.setenv("IDS_NOTIFY_CONFIG", str(path))

    status = client.post("/api/notifications/reload").json()

    assert status["min_risk"] == "Critical"
    assert status["webhook"] == {"format": "discord"}

    path.write_text("{ not json")

    assert client.post("/api/notifications/reload").status_code == 400

    # leave the other tests' webhook settings as they were
    notifier.config = before


def test_websocket_greets_and_streams_batches(client):

    with client.websocket_connect("/ws") as ws:

        assert ws.receive_json()["type"] == "hello"

        client.post("/api/replay", json={"running": True, "rate": 50})

        try:
            for _ in range(10):
                message = ws.receive_json()

                if message["type"] == "batch":
                    assert message["source"] == "replay"
                    assert {"t", "flows", "alerts"} <= set(message["tick"])
                    break
            else:
                pytest.fail("no batch received")
        finally:
            client.post("/api/replay", json={"running": False})


# -- capture control from the dashboard --------------------------------------

def wait_for(condition, seconds=20):

    deadline = time.time() + seconds

    while time.time() < deadline:

        if condition():
            return True

        time.sleep(0.1)

    return False


def test_capture_options_list_interfaces_and_the_data_folder(client):

    options = client.get("/api/capture/options").json()

    assert options["interfaces"]
    assert options["files"] == {"pcap": ["web.pcap"], "csv": ["flows.csv"]}
    assert options["data_dir"].endswith("captures") or "captures" in options["data_dir"]


def test_capture_start_validates_input(client):

    def start(mode, target):
        return client.post("/api/capture/start", json={"mode": mode, "target": target})

    assert start("sniff", "x").status_code == 400
    assert start("interface", "no-such-interface").status_code == 400
    assert start("pcap", "../web.pcap").status_code == 400
    assert start("pcap", "missing.pcap").status_code == 400

    assert client.get("/api/capture").json()["state"] == "stopped"


def test_a_pcap_started_from_the_dashboard_is_scored(client):

    before = client.get("/api/stats?source=capture").json()["total"]

    started = client.post(
        "/api/capture/start", json={"mode": "pcap", "target": "web.pcap"}
    )

    assert started.status_code == 200

    assert wait_for(lambda: client.get("/api/capture").json()["state"] == "finished")

    status = client.get("/api/capture").json()

    assert status["flows"] == 4 and status["packets"] == 20

    assert client.get("/api/stats?source=capture").json()["total"] == before + 4

    flows = client.get("/api/flows?source=capture").json()

    assert {f["src_ip"] for f in flows} >= {"10.0.1.10", "10.0.1.11"}

    sources = client.get("/api/sources").json()

    assert sources["capture"]["flows"] >= 4


def test_only_one_capture_runs_at_a_time_and_it_can_be_stopped(client):

    assert client.post(
        "/api/capture/start", json={"mode": "csv", "target": "flows.csv"}
    ).status_code == 200

    try:
        again = client.post(
            "/api/capture/start", json={"mode": "pcap", "target": "web.pcap"}
        )

        assert again.status_code == 409

        assert wait_for(lambda: client.get("/api/capture").json()["state"] == "running")

    finally:
        stopped = client.post("/api/capture/stop").json()

    assert stopped["state"] == "stopped"


def test_autostart_setting_is_saved(client):

    assert client.get("/api/capture").json()["autostart"] is False

    assert client.post(
        "/api/capture/autostart", json={"enabled": True}
    ).json()["autostart"] is True

    assert client.get("/api/capture/options").json()["saved"] == {
        "mode": "csv", "target": "flows.csv"
    }

    client.post("/api/capture/autostart", json={"enabled": False})


# -- API ingest settings ------------------------------------------------------

def test_ingest_can_be_switched_off_and_on(client):

    rows = client.api.hub.replay_pool.drop(columns="Label").head(2).to_dict("records")

    headers = {"X-API-Key": KEY}

    assert client.get("/api/ingest").json()["enabled"] is True

    assert client.post("/api/ingest", json={"enabled": False}).json()["enabled"] is False

    assert client.post("/api/score", json=rows, headers=headers).status_code == 503

    assert client.post("/api/ingest", json={"enabled": True}).json()["enabled"] is True

    assert client.post("/api/score", json=rows, headers=headers).status_code == 200


def test_a_key_set_by_the_environment_cannot_be_changed_from_the_dashboard(client):

    info = client.get("/api/ingest").json()

    assert info["key_required"] and info["key_source"] == "environment"

    assert client.post("/api/ingest/key").status_code == 409
    assert client.delete("/api/ingest/key").status_code == 409


def test_dashboard_created_keys_work_rotate_and_are_stored_hashed(client, monkeypatch):

    monkeypatch.delenv("IDS_API_KEY")

    rows = client.api.hub.replay_pool.drop(columns="Label").head(2).to_dict("records")

    # no key anywhere: open
    assert client.get("/api/ingest").json()["key_required"] is False
    assert client.post("/api/score", json=rows).status_code == 200

    first = client.post("/api/ingest/key").json()["key"]

    assert client.get("/api/ingest").json()["key_source"] == "dashboard"

    assert client.post("/api/score", json=rows).status_code == 401
    assert client.post("/api/score", json=rows, headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/api/score", json=rows, headers={"X-API-Key": first}).status_code == 200

    # only a hash is kept
    stored = client.api.hub.store.get_setting("api_key_hash")

    assert stored and first not in stored

    second = client.post("/api/ingest/key").json()["key"]

    assert second != first
    assert client.post("/api/score", json=rows, headers={"X-API-Key": first}).status_code == 401
    assert client.post("/api/score", json=rows, headers={"X-API-Key": second}).status_code == 200

    client.delete("/api/ingest/key")

    assert client.post("/api/score", json=rows).status_code == 200


# -- admin token -----------------------------------------------------------

def test_admin_token_protects_the_dashboard_api(client, monkeypatch):

    from starlette.websockets import WebSocketDisconnect

    auth = client.get("/api/auth").json()

    assert auth["required"] is False and auth["ok"] is True

    monkeypatch.setenv("IDS_ADMIN_TOKEN", "s3cret")

    auth = client.get("/api/auth").json()

    assert auth["required"] is True and auth["ok"] is False

    for path in ("/api/stats", "/api/alerts", "/api/capture", "/api/ingest"):
        assert client.get(path).status_code == 401

    assert client.post(
        "/api/capture/start", json={"mode": "pcap", "target": "web.pcap"}
    ).status_code == 401

    wrong = {"Authorization": "Bearer nope"}

    assert client.get("/api/stats", headers=wrong).status_code == 401
    assert client.get("/api/auth", headers=wrong).json()["ok"] is False

    right = {"Authorization": "Bearer s3cret"}

    assert client.get("/api/stats", headers=right).status_code == 200
    auth = client.get("/api/auth", headers=right).json()

    assert auth["required"] is True and auth["ok"] is True and auth["role"] == "admin"

    # flow exporters use the API key, not the admin token
    rows = client.api.hub.replay_pool.drop(columns="Label").head(1).to_dict("records")

    assert client.post("/api/score", json=rows, headers={"X-API-Key": KEY}).status_code == 200

    # the websocket needs it too
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws") as ws:
            ws.receive_json()

    with client.websocket_connect("/ws?token=s3cret") as ws:
        assert ws.receive_json()["type"] == "hello"
