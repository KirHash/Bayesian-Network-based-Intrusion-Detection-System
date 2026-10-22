"""
Everything an admin can do from the dashboard instead of a terminal:
upload data, retrain, roll back, configure notifications, restart, back up,
read logs, see who did what.

The model file is redirected to a temporary copy (IDS_MODEL) so retraining
and rolling back never touch the real one. Tests run in file order.
"""
import importlib
import json
import shutil
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

import lifecycle

from conftest import ROOT, needs_model, write_pcap
from feature_extractor import FEATURES

pytestmark = needs_model

PASSWORD = "correct horse battery"


def synthetic_dataset(path, rows=2500, seed=0):
    """Two clearly different kinds of flow, in the dataset's CSV format."""

    rng = np.random.default_rng(seed)

    def block(label, scale):

        n = rows

        frame = pd.DataFrame({
            "Flow Duration": rng.lognormal(11 - 5 * scale, 1, n),
            "Flow Packets/s": rng.lognormal(3 + 5 * scale, 1, n),
            "Flow Bytes/s": rng.lognormal(8 + 2 * scale, 1, n),
            "Total Fwd Packets": rng.integers(2, 20 + 40 * scale, n),
            "Total Backward Packets": rng.integers(1, 20, n),
            "Average Packet Size": rng.lognormal(5 - 3 * scale, 0.5, n),
            "Packet Length Mean": rng.lognormal(5 - 3 * scale, 0.5, n),
            "Packet Length Std": rng.lognormal(4, 1, n),
            "Flow IAT Mean": rng.lognormal(9 - 6 * scale, 1, n),
            "Fwd IAT Mean": rng.lognormal(9 - 6 * scale, 1, n),
            "Init_Win_bytes_forward": rng.choice([8192, 29200, 64240], n),
            "Destination Port": rng.choice([80, 443, 53] if not scale else [80, 8080], n),
            "Bwd Packets/s": rng.lognormal(3 + 4 * scale, 1, n),
            "Init_Win_bytes_backward": rng.choice([-1, 229, 0], n),
            "min_seg_size_forward": rng.choice([20, 32], n),
            "Max Packet Length": rng.lognormal(6, 1, n),
            "Fwd Packet Length Max": rng.lognormal(5, 1, n),
            "Total Length of Fwd Packets": rng.lognormal(6 - 3 * scale, 1, n),
            "Bwd Packet Length Mean": rng.lognormal(5, 1, n),
            "Fwd IAT Min": rng.lognormal(5, 1, n),
        })[FEATURES]

        frame["Label"] = label

        return frame

    pd.concat([block("BENIGN", 0), block("DDoS", 1)], ignore_index=True).to_csv(
        path, index=False, encoding="latin-1"
    )


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
def client(tmp_path_factory):

    mp = pytest.MonkeyPatch()

    base = tmp_path_factory.mktemp("ops")

    model = base / "model.pkl"

    shutil.copyfile(ROOT / "bayesian_ids.pkl", model)

    (base / "captures").mkdir()
    (base / "dataset").mkdir()

    mp.setenv("IDS_DB", str(base / "ids.db"))
    mp.setenv("IDS_MODEL", str(model))
    mp.setenv("IDS_DATA_DIR", str(base / "captures"))
    mp.setenv("IDS_DATASET_DIR", str(base / "dataset"))
    mp.setenv("IDS_MAX_UPLOAD_MB", "5")

    for name in ("IDS_ADMIN_TOKEN", "IDS_API_KEY", "IDS_SECRET_KEY"):
        mp.delenv(name, raising=False)

    mp.chdir(base)

    api = importlib.reload(importlib.import_module("api"))

    with TestClient(api.app) as client:

        client.api = api
        client.base = base
        client.model = model

        yield client

    mp.undo()


def wait_for(condition, seconds=180):

    deadline = time.time() + seconds

    while time.time() < deadline:

        value = condition()

        if value:
            return value

        time.sleep(0.3)

    return None


def upload(client, area, name, content, headers=None, **params):

    return client.put(
        f"/api/files/{area}/{name}", content=content, headers=headers or {},
        params=params
    )


# -- uploads -----------------------------------------------------------------------

def test_a_pcap_can_be_uploaded_listed_used_and_deleted(client):

    source = client.base / "src.pcap"

    write_pcap(source, flows=3)

    response = upload(client, "captures", "web.pcap", source.read_bytes())

    assert response.status_code == 200, response.text
    assert response.json() == {"name": "web.pcap", "size": source.stat().st_size}

    listing = client.get("/api/files").json()

    assert [f["name"] for f in listing["captures"]] == ["web.pcap"]

    # the Capture panel's file list sees it, and can read it
    assert client.get("/api/capture/options").json()["files"]["pcap"] == ["web.pcap"]

    assert client.post("/api/capture/start", json={"mode": "pcap", "target": "web.pcap"}).status_code == 200

    assert wait_for(lambda: client.get("/api/capture").json()["state"] == "finished", 30)

    assert client.get("/api/capture").json()["flows"] == 3

    assert client.delete("/api/files/captures/web.pcap").status_code == 200
    assert client.get("/api/files").json()["captures"] == []
    assert client.delete("/api/files/captures/web.pcap").status_code == 404


def test_uploads_are_refused_when_unsafe_or_wrong(client):

    pcap = (client.base / "src.pcap").read_bytes()

    # names
    for name in ("x.exe", ".hidden.pcap", "..%2Fx.pcap"):
        assert upload(client, "captures", name, pcap).status_code in (400, 404, 405, 422), name  # 405: never reaches the upload route

    assert upload(client, "nowhere", "x.pcap", pcap).status_code == 400

    # content
    fake = upload(client, "captures", "fake.pcap", b"MZ this is not a capture")

    assert fake.status_code == 400 and "pcap" in fake.json()["detail"]

    assert upload(client, "captures", "empty.pcap", b"").status_code == 400

    assert upload(client, "dataset", "x.pcap", pcap).status_code == 400

    # nothing half-written is left behind
    leftovers = [p.name for p in (client.base / "captures").iterdir()]

    assert leftovers == []


def test_existing_files_are_not_overwritten_unless_asked(client):

    pcap = (client.base / "src.pcap").read_bytes()

    assert upload(client, "captures", "keep.pcap", pcap).status_code == 200

    again = upload(client, "captures", "keep.pcap", pcap)

    assert again.status_code == 409 and "replace" in again.json()["detail"]

    assert upload(client, "captures", "keep.pcap", pcap, replace="true").status_code == 200

    client.delete("/api/files/captures/keep.pcap")


def test_the_size_limit_is_enforced_while_streaming(client):

    big = b"\xd4\xc3\xb2\xa1" + b"\x00" * (6 * 1024 * 1024)

    response = upload(client, "captures", "big.pcap", big)

    assert response.status_code == 413

    # the connection is closed so the rest of the upload is not read and thrown away
    assert response.headers["connection"] == "close"
    assert list((client.base / "captures").iterdir()) == []


def test_dataset_csvs_must_have_the_columns_the_model_needs(client):

    bad = upload(client, "dataset", "bad.csv", b"a,b,c\n1,2,3\n")

    assert bad.status_code == 400 and "Label" in bad.json()["detail"]

    assert list((client.base / "dataset").iterdir()) == []


# -- retraining, evaluating, rolling back ----------------------------------------------------

def test_training_needs_a_dataset(client):

    refused = client.post("/api/jobs", json={"kind": "train"})

    assert refused.status_code == 400 and "dataset" in refused.json()["detail"].lower()

    assert client.post("/api/jobs", json={"kind": "rm -rf"}).status_code == 400


def test_a_dataset_uploaded_from_the_dashboard_is_summarised(client):

    synthetic_dataset(client.base / "synthetic.csv")

    response = upload(client, "dataset", "synthetic.csv", (client.base / "synthetic.csv").read_bytes())

    # (the file is bigger than the 5 MB test limit if it were not compressed small)
    assert response.status_code == 200, response.text

    def labels():

        entry = client.get("/api/files").json()["dataset"]

        return entry and entry[0]["labels"]

    assert wait_for(labels, 60) == {"BENIGN": 2500, "DDoS": 2500}

    assert client.get("/api/files").json()["dataset"][0]["rows"] == 5000

    assert client.get("/api/model").json()["dataset_files"] == 1


def test_retraining_from_the_dashboard_replaces_and_reloads_the_model(client):

    # the project's own model files must stay exactly as they are
    real = [ROOT / "bayesian_ids.pkl", ROOT / "model_card.json"]

    untouched = [p.read_bytes() for p in real]

    before = client.get("/api/model").json()

    assert before["previous_available"] is False

    started = client.post("/api/jobs", json={"kind": "train"})

    assert started.status_code == 200, started.text

    job_id = started.json()["id"]

    # only one job at a time
    assert client.post("/api/jobs", json={"kind": "evaluate"}).status_code == 409

    def finished():

        job = client.get(f"/api/jobs/{job_id}").json()

        return job if job["state"] != "running" else None

    job = wait_for(finished, 240)

    assert job is not None, "training did not finish"
    assert job["state"] == "succeeded", "\n".join(job["output"][-15:])

    assert any("Model trained successfully" in line for line in job["output"])

    after = client.get("/api/model").json()

    # the running server is now using the new model, with its held-out numbers
    assert after["card"]["trained_at"] != before["card"]["trained_at"]
    assert set(after["classes"]) == {"BENIGN", "DDoS"}
    assert after["card"]["test"]["recall"] > 0.9 and after["card"]["test"]["rows"] > 1000
    assert after["previous_available"] is True

    # scoring uses it straight away
    assert client.get("/api/healthz").json()["status"] == "ok"

    assert [p.read_bytes() for p in real] == untouched, "retraining touched the real model files"

    # the card of a model kept elsewhere is written beside it
    assert (client.base / "model.pkl.card.json").exists()


def test_output_can_be_followed_in_pieces_and_jobs_are_listed(client):

    jobs = client.get("/api/jobs").json()

    assert jobs["jobs"][0]["kind"] == "train" and jobs["jobs"][0]["state"] == "succeeded"
    assert {"train", "evaluate", "compare"} <= set(jobs["kinds"])

    job_id = jobs["jobs"][0]["id"]

    full = client.get(f"/api/jobs/{job_id}").json()

    rest = client.get(f"/api/jobs/{job_id}", params={"after": full["lines"] - 2}).json()

    assert rest["output"] == full["output"][-2:]

    assert client.get("/api/jobs/9999").status_code == 404


def test_evaluation_runs_as_a_job_too(client):

    job_id = client.post("/api/jobs", json={"kind": "evaluate"}).json()["id"]

    job = wait_for(
        lambda: (j := client.get(f"/api/jobs/{job_id}").json())["state"] != "running" and j, 180
    )

    assert job["state"] == "succeeded", "\n".join(job["output"][-10:])

    assert any(line.startswith("Accuracy:") for line in job["output"])


def test_a_running_job_can_be_cancelled(client):

    job_id = client.post("/api/jobs", json={"kind": "train"}).json()["id"]

    assert client.post(f"/api/jobs/{job_id}/cancel").status_code == 200

    job = wait_for(
        lambda: (j := client.get(f"/api/jobs/{job_id}").json())["state"] != "running" and j, 30
    )

    assert job["state"] == "cancelled"

    assert client.post(f"/api/jobs/{job_id}/cancel").status_code == 409

    # the model on disk is still loadable after a cancelled run
    assert client.post("/api/model/reload").status_code == 200


def test_rolling_back_restores_the_previous_model(client):

    current = client.get("/api/model").json()["card"]["trained_at"]

    assert client.get("/api/model").json()["previous_available"] is True

    rolled = client.post("/api/model/rollback")

    assert rolled.status_code == 200, rolled.text

    older = rolled.json()["card"]["trained_at"]

    assert older != current

    # the real model knows many attack types; the synthetic one two
    assert len(rolled.json()["classes"]) > 5

    # rolling back again swaps forward
    assert client.post("/api/model/rollback").json()["card"]["trained_at"] == current


def test_rollback_without_a_previous_model_is_a_clear_error(client):

    previous = str(client.model) + ".previous"

    shutil.copyfile(previous, previous + ".keep")

    import os

    os.remove(previous)

    refused = client.post("/api/model/rollback")

    assert refused.status_code == 400 and "no previous" in refused.json()["detail"]

    os.replace(previous + ".keep", previous)


def test_a_corrupt_model_file_is_rejected_and_the_old_model_keeps_running(client):

    good = client.model.read_bytes()

    client.model.write_bytes(b"this is not a pickle")

    response = client.post("/api/model/reload")

    assert response.status_code == 400 and "could not load" in response.json()["detail"]

    assert client.get("/api/healthz").json()["status"] == "ok"
    assert client.get("/api/model").json()["classes"]

    client.model.write_bytes(good)

    assert client.post("/api/model/reload").status_code == 200


# -- notification settings ---------------------------------------------------------------

def test_notifications_are_configured_from_the_dashboard(client, webhook):

    url, received = webhook

    assert client.get("/api/notifications/config").json() == {"source": "none", "settings": None}

    settings = {
        "min_risk": "Medium", "sources": ["capture", "api", "replay"], "window_seconds": 1,
        "base_url": "http://127.0.0.1:8000",
        "webhook": {"enabled": True, "format": "slack", "url": url},
        "email": {"enabled": False}
    }

    saved = client.put("/api/notifications/config", json=settings)

    assert saved.status_code == 200, saved.text

    body = saved.json()

    assert body["source"] == "dashboard" and url not in json.dumps(body)
    assert body["settings"]["webhook"]["has_url"] is True

    # it works at once, no restart or reload
    assert client.get("/api/notifications").json()["channels"] == ["webhook"]
    assert client.get("/api/notifications").json()["source"] == "dashboard"

    assert client.post("/api/notifications/test").json() == {"webhook": {"ok": True}}
    assert "test notification" in received[-1]["text"]

    # the stored copy is encrypted
    raw = sqlite3.connect(client.base / "ids.db").execute(
        "SELECT value FROM settings WHERE key = 'notify_config'"
    ).fetchone()[0]

    assert url not in raw and "enc:" in raw


def test_leaving_the_url_blank_keeps_it_and_bad_settings_are_refused(client, webhook):

    url, received = webhook

    update = {
        "min_risk": "Critical", "sources": ["capture"], "window_seconds": 5,
        "webhook": {"enabled": True, "format": "discord"}, "email": {"enabled": False}
    }

    assert client.put("/api/notifications/config", json=update).status_code == 200

    client.post("/api/notifications/test")

    assert "test notification" in (received[-1].get("content") or received[-1].get("text"))

    for bad in (
        {**update, "min_risk": "Low"},
        {**update, "webhook": {"enabled": True, "url": "ftp://nope"}},
        {**update, "email": {"enabled": True, "host": ""}},
    ):
        assert client.put("/api/notifications/config", json=bad).status_code == 400


def test_losing_the_key_file_leaves_a_running_server_that_explains_itself(client, webhook):

    url, _ = webhook

    key_file = client.base / "ids.db.key"

    assert key_file.exists()

    saved = key_file.read_bytes()

    notifier = client.api.hub.notifier

    # what a restart after restoring a backup without its key would find
    key_file.unlink()

    notifier.box = type(notifier.box)(key_file, env={})

    notifier.load_managed()

    status = client.get("/api/notifications").json()

    assert status["channels"] == [] and "cannot be read" in status["problem"]

    config = client.get("/api/notifications/config").json()

    assert config["problem"] and config["settings"]["webhook"]["has_url"]

    assert client.get("/api/healthz").json()["status"] == "ok"

    # entering the secrets again repairs it, with the new key
    again = client.put("/api/notifications/config", json={
        "min_risk": "Medium", "sources": ["capture"], "window_seconds": 1,
        "webhook": {"enabled": True, "format": "slack", "url": url}, "email": {"enabled": False}
    })

    assert again.status_code == 200 and again.json()["source"] == "dashboard"

    assert client.get("/api/notifications").json()["problem"] is None
    assert client.post("/api/notifications/test").json() == {"webhook": {"ok": True}}

    # put the original key back so later tests are unaffected
    key_file.write_bytes(saved)


# -- the server itself ------------------------------------------------------------------------

def test_server_facts_logs_and_audit(client):

    facts = client.get("/api/server").json()

    assert facts["pid"] > 0 and facts["python"] and facts["database"].endswith("ids.db")
    assert facts["autostart"]["supported"] in (True, False)

    messages = [line["message"] for line in client.get("/api/logs").json()]

    assert any("server started" in m for m in messages)
    assert any("model reloaded" in m for m in messages)

    assert client.get("/api/logs", params={"level": "LOUD"}).status_code == 400

    audit = client.get("/api/audit").json()

    actions = {a["action"] for a in audit}

    assert "POST /api/jobs" in actions
    assert "PUT /api/files/captures/web.pcap" in actions or any("web.pcap" in a["detail"] for a in audit)
    assert "PUT /api/notifications/config" in actions

    assert all(a["actor"] == "local" for a in audit)

    # the secret never reaches the log or the audit trail
    everything = json.dumps(audit) + json.dumps(client.get("/api/logs").json())

    assert "hooks" not in everything and "127.0.0.1:" + str(client.base) not in everything


def test_backup_is_a_downloadable_database_copy(client):

    response = client.get("/api/backup")

    assert response.status_code == 200
    assert "ids-backup-" in response.headers["content-disposition"]
    assert response.content.startswith(b"SQLite format 3")

    path = client.base / "downloaded.db"

    path.write_bytes(response.content)

    tables = {r[0] for r in sqlite3.connect(path).execute("SELECT name FROM sqlite_master")}

    assert {"alerts", "users", "settings", "audit"} <= tables


def test_restart_is_requested_after_the_response(client, monkeypatch):

    called = threading.Event()

    monkeypatch.setattr(lifecycle, "restart", called.set)

    response = client.post("/api/server/restart")

    assert response.status_code == 200 and response.json() == {"restarting": True}

    # it fires shortly after, not before the answer went out
    assert called.wait(5)


def test_start_at_login_is_switched_from_the_dashboard(client, monkeypatch):

    class Fake:

        supported = True

        def __init__(self):
            self.on = False
            self.enabled_with = None

        def enabled(self):
            return self.on

        def enable(self, command, cwd, log_path):
            self.on = True
            self.enabled_with = (command, cwd, log_path)

        def disable(self):
            self.on = False

    fake = Fake()

    monkeypatch.setattr(client.api.hub, "autostart", fake)

    assert client.get("/api/server").json()["autostart"] == {"supported": True, "enabled": False}

    on = client.post("/api/server/autostart", json={"enabled": True})

    assert on.status_code == 200 and on.json()["autostart"]["enabled"] is True

    command, cwd, log_path = fake.enabled_with

    assert command and log_path.endswith("server.log")

    off = client.post("/api/server/autostart", json={"enabled": False})

    assert off.json()["autostart"]["enabled"] is False


def test_a_failure_to_set_up_start_at_login_is_reported(client, monkeypatch):

    class Broken:

        supported = True

        def enabled(self):
            return False

        def enable(self, *args):
            raise RuntimeError("Access is denied")

    monkeypatch.setattr(client.api.hub, "autostart", Broken())

    response = client.post("/api/server/autostart", json={"enabled": True})

    assert response.status_code == 500 and "Access is denied" in response.json()["detail"]


# -- who may do any of this ------------------------------------------------------------------

ADMIN_ONLY = [
    ("GET", "/api/files"), ("PUT", "/api/files/captures/x.pcap"),
    ("DELETE", "/api/files/captures/x.pcap"), ("GET", "/api/jobs"),
    ("POST", "/api/jobs"), ("GET", "/api/jobs/1"), ("POST", "/api/jobs/1/cancel"),
    ("POST", "/api/model/reload"), ("POST", "/api/model/rollback"),
    ("GET", "/api/notifications/config"), ("PUT", "/api/notifications/config"),
    ("GET", "/api/server"), ("POST", "/api/server/restart"),
    ("POST", "/api/server/autostart"), ("GET", "/api/backup"),
    ("GET", "/api/logs"), ("GET", "/api/audit"),
]


def test_only_admins_reach_the_operations_endpoints(client, monkeypatch):

    # (a restart or a start-at-login request must not really run if one slips through)
    monkeypatch.setattr(lifecycle, "restart", lambda: None)

    admin = client.post("/api/users", json={"username": "root", "password": PASSWORD, "role": "admin"})

    assert admin.status_code == 200

    for name, role in (("vera", "viewer"), ("alan", "analyst")):

        token = client.post("/api/login", json={"username": "root", "password": PASSWORD}).json()["token"]

        client.post("/api/users", headers={"Authorization": f"Bearer {token}"},
                    json={"username": name, "password": PASSWORD, "role": role})

    for name in ("vera", "alan"):

        token = client.post("/api/login", json={"username": name, "password": PASSWORD}).json()["token"]

        headers = {"Authorization": f"Bearer {token}"}

        for method, path in ADMIN_ONLY:

            response = client.request(method, path, headers=headers, json={} if method in ("POST", "PUT") else None)

            assert response.status_code == 403, f"{name} reached {method} {path}"

    # without any login at all
    for method, path in ADMIN_ONLY:
        assert client.request(method, path).status_code == 401, f"{method} {path}"

    # and the refusals were written to the audit trail
    root = {"Authorization": "Bearer " + client.post(
        "/api/login", json={"username": "root", "password": PASSWORD}).json()["token"]}

    denied = [a for a in client.get("/api/audit", headers=root).json() if a["action"].startswith("denied")]

    assert {a["actor"] for a in denied} == {"vera", "alan"}

    logins = [a for a in client.get("/api/audit", headers=root).json() if a["action"] == "login"]

    assert {a["actor"] for a in logins} >= {"root", "vera", "alan"}
