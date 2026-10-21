"""
Authentication, roles and attribution through the real API.

The tests run in file order because they build on each other: the server
starts open (no accounts), the first admin is created, then everything
requires a login.
"""
import importlib

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from conftest import needs_model

pytestmark = needs_model

PASSWORD = "correct horse battery"


@pytest.fixture(scope="module")
def client(tmp_path_factory):

    mp = pytest.MonkeyPatch()

    base = tmp_path_factory.mktemp("auth")

    mp.setenv("IDS_DB", str(base / "ids.db"))
    mp.setenv("IDS_DATA_DIR", str(base))
    mp.setenv("IDS_DEMO_DATA", str(base / "no-demo-here"))

    for name in ("IDS_ADMIN_TOKEN", "IDS_API_KEY"):
        mp.delenv(name, raising=False)

    api = importlib.reload(importlib.import_module("api"))

    with TestClient(api.app) as client:

        client.api = api

        yield client

    mp.undo()


def sign_in(client, username, password=PASSWORD):

    response = client.post(
        "/api/login", json={"username": username, "password": password}
    )

    assert response.status_code == 200, response.text

    return {"Authorization": f"Bearer {response.json()['token']}"}


def make_alert():

    return client_alert


client_alert = {
    "time": "2026-01-01T10:00:00", "source": "capture", "attack_type": "DDoS",
    "reason": "classifier", "risk": "High", "probability": 99.0,
    "surprise": 1.0, "label": None, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
    "dst_port": 80, "posterior": {"DDoS": 1.0}, "features": {}
}


# -- before any account exists ------------------------------------------------

def test_health_is_public_and_reports_the_parts(client):

    health = client.get("/api/healthz")

    assert health.status_code == 200

    body = health.json()

    assert body["status"] == "ok" and body["model"] and body["database"]
    assert body["capture"] == "stopped"


def test_with_no_accounts_the_server_is_open(client):

    auth = client.get("/api/auth").json()

    assert auth["required"] is False and auth["ok"] is True
    assert auth["methods"] == {"password": False, "token": False}

    assert client.get("/api/stats").status_code == 200


def test_the_demo_without_its_data_is_a_clear_error_not_a_crash(client):

    response = client.post("/api/replay", json={"running": True})

    assert response.status_code == 400
    assert "demo data not found" in response.json()["detail"]

    assert client.get("/api/stats").status_code == 200


def test_the_first_account_must_be_an_admin(client):

    refused = client.post("/api/users", json={
        "username": "kim", "password": PASSWORD, "role": "viewer"
    })

    assert refused.status_code == 400 and "first account" in refused.json()["detail"]

    assert client.post("/api/users", json={
        "username": "root", "password": PASSWORD, "role": "admin"
    }).status_code == 200


# -- once accounts exist -----------------------------------------------------

def test_everything_now_needs_a_login(client):

    for path in ("/api/stats", "/api/alerts", "/api/capture", "/api/users"):
        assert client.get(path).status_code == 401

    assert client.post("/api/capture/stop").status_code == 401

    auth = client.get("/api/auth").json()

    assert auth["required"] is True and auth["ok"] is False
    assert auth["methods"]["password"] is True

    # still public
    assert client.get("/api/healthz").status_code == 200


def test_wrong_credentials_are_refused_without_saying_which_part(client):

    for name, password in (("root", "wrong password!"), ("ghost", PASSWORD)):

        response = client.post(
            "/api/login", json={"username": name, "password": password}
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "wrong username or password"


def test_signing_in_and_out(client):

    headers = sign_in(client, "root")

    auth = client.get("/api/auth", headers=headers).json()

    assert auth["ok"] and auth["user"] == "root" and auth["role"] == "admin"

    assert client.get("/api/stats", headers=headers).status_code == 200

    assert client.post("/api/logout", headers=headers).status_code == 200

    assert client.get("/api/stats", headers=headers).status_code == 401


def test_admins_create_users_and_never_see_hashes(client):

    admin = sign_in(client, "root")

    for name, role in (("vera", "viewer"), ("alan", "analyst")):

        assert client.post("/api/users", headers=admin, json={
            "username": name, "password": PASSWORD, "role": role
        }).status_code == 200

    users = client.get("/api/users", headers=admin).json()

    assert [(u["username"], u["role"]) for u in users] == [
        ("alan", "analyst"), ("root", "admin"), ("vera", "viewer")
    ]

    assert all("password_hash" not in u for u in users)

    duplicate = client.post("/api/users", headers=admin, json={
        "username": "VERA", "password": PASSWORD, "role": "viewer"
    })

    assert duplicate.status_code == 400


# -- what each role may do ----------------------------------------------------

def test_a_viewer_can_look_but_not_touch(client):

    ids = client.api.hub.store.add_alerts([dict(client_alert)])

    viewer = sign_in(client, "vera")

    for path in ("/api/stats", "/api/alerts", f"/api/alerts/{ids[0]}",
                 "/api/capture", "/api/ingest", "/api/notifications"):
        assert client.get(path, headers=viewer).status_code == 200, path

    denied = [
        client.patch(f"/api/alerts/{ids[0]}", headers=viewer, json={"status": "resolved"}),
        client.post("/api/alerts/bulk", headers=viewer, json={"ids": ids, "status": "resolved"}),
        client.post("/api/capture/start", headers=viewer, json={"mode": "pcap", "target": "x.pcap"}),
        client.post("/api/ingest", headers=viewer, json={"enabled": False}),
        client.post("/api/ingest/key", headers=viewer),
        client.post("/api/notifications/test", headers=viewer),
        client.post("/api/replay", headers=viewer, json={"running": True}),
        client.post("/api/reset", headers=viewer),
        client.get("/api/users", headers=viewer),
        client.get("/api/capture/options", headers=viewer),
    ]

    assert [r.status_code for r in denied] == [403] * len(denied)

    assert "role" in denied[0].json()["detail"]


def test_an_analyst_handles_alerts_and_nothing_else(client):

    ids = [client.api.hub.store.add_alerts([dict(client_alert)])[0]]

    analyst = sign_in(client, "alan")

    assert client.patch(f"/api/alerts/{ids[0]}", headers=analyst,
                        json={"status": "investigating"}).status_code == 200

    assert client.post("/api/alerts/bulk", headers=analyst,
                       json={"ids": ids, "status": "resolved"}).status_code == 200

    for response in (
        client.post("/api/capture/start", headers=analyst, json={"mode": "pcap", "target": "x"}),
        client.post("/api/ingest", headers=analyst, json={"enabled": False}),
        client.get("/api/users", headers=analyst),
    ):
        assert response.status_code == 403


def test_changes_are_attributed_to_the_signed_in_user_not_to_the_request(client):

    alert_id = client.api.hub.store.add_alerts([dict(client_alert)])[0]

    analyst = sign_in(client, "alan")

    # a client cannot claim to be someone else
    client.patch(f"/api/alerts/{alert_id}", headers=analyst,
                 json={"status": "investigating", "actor": "someone-else"})

    root = sign_in(client, "root")

    client.post("/api/alerts/bulk", headers=root,
                json={"ids": [alert_id], "status": "resolved", "actor": "forged"})

    events = client.get(f"/api/alerts/{alert_id}", headers=root).json()["events"]

    assert [(e["actor"], e["action"]) for e in events] == [
        ("alan", "status"), ("root", "status")
    ]


# -- managing users ------------------------------------------------------------

def test_roles_change_and_take_effect_immediately(client):

    admin = sign_in(client, "root")

    analyst = sign_in(client, "alan")

    ids = client.api.hub.store.add_alerts([dict(client_alert)])

    assert client.patch(f"/api/alerts/{ids[0]}", headers=analyst,
                        json={"status": "resolved"}).status_code == 200

    client.patch("/api/users/alan", headers=admin, json={"role": "viewer"})

    assert client.patch(f"/api/alerts/{ids[0]}", headers=analyst,
                        json={"status": "new"}).status_code == 403

    client.patch("/api/users/alan", headers=admin, json={"role": "analyst"})


def test_resetting_a_password_ends_that_users_sessions(client):

    admin = sign_in(client, "root")

    old = sign_in(client, "alan")

    assert client.patch("/api/users/alan", headers=admin,
                        json={"password": "a brand new password"}).status_code == 200

    assert client.get("/api/stats", headers=old).status_code == 401

    sign_in(client, "alan", "a brand new password")

    client.patch("/api/users/alan", headers=admin, json={"password": PASSWORD})


def test_disabled_users_are_locked_out_at_once(client):

    admin = sign_in(client, "root")

    session = sign_in(client, "vera")

    client.patch("/api/users/vera", headers=admin, json={"disabled": True})

    assert client.get("/api/stats", headers=session).status_code == 401

    assert client.post("/api/login", json={
        "username": "vera", "password": PASSWORD
    }).status_code == 401

    client.patch("/api/users/vera", headers=admin, json={"disabled": False})

    sign_in(client, "vera")


def test_admins_cannot_lock_themselves_or_everyone_out(client):

    admin = sign_in(client, "root")

    assert client.delete("/api/users/root", headers=admin).status_code == 409
    assert client.patch("/api/users/root", headers=admin,
                        json={"disabled": True}).status_code == 409

    # the last admin cannot be demoted either
    demote = client.patch("/api/users/root", headers=admin, json={"role": "viewer"})

    assert demote.status_code == 400 and "last enabled admin" in demote.json()["detail"]

    assert client.patch("/api/users/nobody", headers=admin,
                        json={"role": "viewer"}).status_code == 400


def test_bad_user_input_is_a_400(client):

    admin = sign_in(client, "root")

    for body in (
        {"username": "x", "password": PASSWORD, "role": "viewer"},
        {"username": "newbie", "password": "short", "role": "viewer"},
        {"username": "newbie", "password": PASSWORD, "role": "emperor"},
    ):
        assert client.post("/api/users", headers=admin, json=body).status_code == 400


def test_deleting_a_user(client):

    admin = sign_in(client, "root")

    client.post("/api/users", headers=admin, json={
        "username": "temp", "password": PASSWORD, "role": "viewer"
    })

    assert client.delete("/api/users/temp", headers=admin).status_code == 200
    assert client.delete("/api/users/temp", headers=admin).status_code == 400


# -- the other doors ------------------------------------------------------------

def test_the_websocket_needs_a_session(client):

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws") as ws:
            ws.receive_json()

    token = sign_in(client, "vera")["Authorization"].removeprefix("Bearer ")

    with client.websocket_connect(f"/ws?token={token}") as ws:
        assert ws.receive_json()["type"] == "hello"


def test_flow_exporters_are_unaffected_by_logins(client):

    row = [{"Destination Port": 80}]

    # no API key configured: open, even though dashboard logins are required
    response = client.post("/api/score", json=row)

    assert response.status_code == 400
    assert "missing flow columns" in response.json()["detail"]


def test_the_shared_admin_token_still_works_as_an_admin(client, monkeypatch):

    monkeypatch.setenv("IDS_ADMIN_TOKEN", "break-glass")

    headers = {"Authorization": "Bearer break-glass"}

    assert client.get("/api/users", headers=headers).status_code == 200

    auth = client.get("/api/auth", headers=headers).json()

    assert auth["user"] == "admin-token" and auth["role"] == "admin"
    assert auth["methods"]["token"] is True

    assert client.get("/api/users", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_repeated_wrong_passwords_lock_the_login(client):

    for _ in range(5):
        client.post("/api/login", json={"username": "root", "password": "nope nope nope"})

    locked = client.post("/api/login", json={"username": "root", "password": PASSWORD})

    assert locked.status_code == 429
    assert int(locked.headers["Retry-After"]) > 0

    # reset the in-memory counters so later tests are not affected
    client.api.hub.accounts.failures.clear()


# -- browser hardening ------------------------------------------------------

def test_responses_carry_security_headers(client):

    for path in ("/api/healthz", "/api/auth", "/"):

        headers = client.get(path).headers

        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert headers["referrer-policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in headers["content-security-policy"]
        assert "script-src" not in headers["content-security-policy"]
        assert "strict-transport-security" not in headers

    # refusals are covered too
    assert client.get("/api/stats").headers["x-frame-options"] == "DENY"


def test_hsts_is_added_when_the_connection_is_encrypted(client):

    direct = client.get("https://testserver/api/healthz")

    assert "max-age" in direct.headers["strict-transport-security"]

    proxied = client.get("/api/healthz", headers={"X-Forwarded-Proto": "https"})

    assert "max-age" in proxied.headers["strict-transport-security"]
