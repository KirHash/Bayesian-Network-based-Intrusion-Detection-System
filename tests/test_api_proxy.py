"""
The proxy as an admin drives it from the dashboard: choose an engine, set it up,
start it, test it, read its certificate, stop it, and put the dashboard itself in
proxy mode. Real Caddy / nginx programs are used where installed.
"""
import importlib
import json
import socket
import sys

import pytest
from fastapi.testclient import TestClient

import proxy_manager as pm
from conftest import needs_model
from test_proxy_manager import REAL_BIN, Upstream, free_port, needs_caddy, needs_nginx

pytestmark = needs_model

PASSWORD = "correct horse battery"

CERT = """-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUEXAMPLEEXAMPLEEXAMPLEEXAMPLEwCgYIKoZIzj0EAwIw
-----END CERTIFICATE-----
"""

KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEXAMPLEEXAMPLEEXAMPL
-----END PRIVATE KEY-----
"""


@pytest.fixture(scope="module")
def upstream():

    up = Upstream()

    yield up

    up.close()


@pytest.fixture(scope="module")
def client(tmp_path_factory, upstream):

    mp = pytest.MonkeyPatch()

    base = tmp_path_factory.mktemp("proxyapi")

    mp.setenv("IDS_DB", str(base / "ids.db"))
    mp.setenv("IDS_DATA_DIR", str(base / "captures"))
    mp.setenv("IDS_CERT_DIR", str(base / "certs"))
    mp.setenv("IDS_PROXY_DIR", str(base / "proxy"))
    mp.setenv("IDS_PROXY_BIN", str(REAL_BIN))
    mp.setenv("IDS_MODEL", str(pm.HERE / "bayesian_ids.pkl"))

    for name in ("IDS_ADMIN_TOKEN", "IDS_API_KEY", "IDS_SECRET_KEY"):
        mp.delenv(name, raising=False)

    mp.chdir(base)

    api = importlib.reload(importlib.import_module("api"))

    # the proxy should reach the stand-in, not whatever listens on port 8000
    api.real_dashboard_upstream = api.dashboard_upstream
    mp.setattr(api, "dashboard_upstream", lambda: upstream.address)

    with TestClient(api.app) as client:

        client.api = api
        client.base = base

        yield client

    mp.undo()


def put(client, settings):
    return client.put("/api/proxy/settings", json=settings)


# -- status and settings ---------------------------------------------------------

def test_status_describes_the_engines_and_the_dashboard(client, upstream):

    status = client.get("/api/proxy").json()

    assert set(status["installed"]) == {"caddy", "nginx"}
    assert status["running"] is False and status["url"] == "https://localhost:8443"
    assert status["upstream"] == upstream.address
    assert status["bind"] == ["127.0.0.1", "::1"]
    assert status["upload_mb"] >= 4096
    assert status["dashboard_behind_proxy"] is False

    # pytest is not serve.py, so proxy mode cannot be switched from here
    assert status["can_switch_proxy_mode"] is False


@pytest.mark.parametrize("settings, message", [
    ({"engine": "apache"}, "engine"),
    ({"port": 99999}, "port"),
    ({"address": "not valid!"}, "address"),
    ({"engine": "caddy", "tls": "maybe"}, "TLS for Caddy"),
    ({"engine": "nginx", "cert": "x.crt"}, "certificates folder"),
])
def test_bad_settings_come_back_as_400_with_the_reason(client, settings, message):

    response = put(client, settings)

    assert response.status_code == 400 and message in response.json()["detail"]


def test_settings_are_saved(client):

    saved = put(client, {"engine": "caddy", "port": 9443, "address": "localhost"}).json()

    assert saved["settings"]["port"] == 9443

    assert client.get("/api/proxy").json()["settings"]["port"] == 9443


def test_starting_something_that_is_not_installed_is_explained(client, monkeypatch):

    monkeypatch.setenv("IDS_PROXY_BIN", str(client.base / "empty-bin"))

    put(client, {"engine": "nginx"})

    response = client.post("/api/proxy/start")

    assert response.status_code == 400 and "not installed" in response.json()["detail"]

    monkeypatch.setenv("IDS_PROXY_BIN", str(REAL_BIN))


def test_installing_an_unknown_engine_is_refused(client):

    assert client.post("/api/proxy/install", json={"engine": "apache"}).status_code == 400


# -- certificates uploaded for nginx ---------------------------------------------------------

def test_certificate_files_are_checked_when_uploaded(client):

    assert client.put("/api/files/certs/site.crt", content=CERT.encode()).status_code == 200
    assert client.put("/api/files/certs/site.key", content=KEY.encode()).status_code == 200

    # a key file must hold a key, a certificate file a certificate, and both must be PEM
    assert client.put("/api/files/certs/bad.key", content=CERT.encode()).status_code == 400
    assert client.put("/api/files/certs/bad.crt", content=KEY.encode()).status_code == 400
    assert client.put("/api/files/certs/plain.pem", content=b"hello").status_code == 400
    assert client.put("/api/files/certs/x.exe", content=CERT.encode()).status_code == 400

    listing = client.get("/api/files").json()

    assert [f["name"] for f in listing["certs"]] == ["site.key", "site.crt"] or \
        sorted(f["name"] for f in listing["certs"]) == ["site.crt", "site.key"]

    assert sorted(client.get("/api/proxy").json()["certificates"]) == ["site.crt", "site.key"]

    client.delete("/api/files/certs/site.crt")
    client.delete("/api/files/certs/site.key")


def test_nginx_settings_can_use_uploaded_certificates_only_if_they_exist(client):

    assert put(client, {"engine": "nginx", "cert": "gone.crt", "key": "gone.key"}).status_code == 400

    client.put("/api/files/certs/site.crt", content=CERT.encode())
    client.put("/api/files/certs/site.key", content=KEY.encode())

    saved = put(client, {"engine": "nginx", "cert": "site.crt", "key": "site.key"}).json()

    assert saved["settings"]["tls"] == "files"

    put(client, {"engine": "nginx", "cert": None, "key": None})

    client.delete("/api/files/certs/site.crt")
    client.delete("/api/files/certs/site.key")


# -- running it ---------------------------------------------------------------------------------

@pytest.fixture(params=[
    pytest.param("caddy", marks=needs_caddy),
    pytest.param("nginx", marks=needs_nginx),
])
def engine(request, client):

    put(client, {"engine": request.param, "port": free_port(), "address": "localhost",
                 "expose": False, "autostart": False})

    yield request.param

    client.post("/api/proxy/stop")


def test_the_proxy_runs_from_start_to_stop_through_the_dashboard(client, engine, upstream):

    started = client.post("/api/proxy/start")

    assert started.status_code == 200, started.text
    assert started.json()["running"] is True and started.json()["pid"]

    tested = client.post("/api/proxy/test").json()

    assert tested["ok"] and tested["reaches_dashboard"] and tested["tls"].startswith("TLS")

    # starting again is harmless
    assert client.post("/api/proxy/start").json()["running"] is True

    restarted = client.post("/api/proxy/restart")

    assert restarted.status_code == 200 and restarted.json()["running"] is True
    assert client.post("/api/proxy/test").json()["ok"]

    stopped = client.post("/api/proxy/stop").json()

    assert stopped["running"] is False

    assert client.post("/api/proxy/test").status_code == 400


def test_the_certificate_can_be_inspected_and_downloaded(client, engine):

    client.post("/api/proxy/start")

    details = client.get("/api/proxy/certificate").json()

    assert details["fingerprint"].count(":") == 31 and details["expires"]

    download = client.get("/api/proxy/certificate/download")

    assert download.status_code == 200
    assert download.content.startswith(b"-----BEGIN CERTIFICATE-----")
    assert "ids-proxy-certificate.crt" in download.headers["content-disposition"]

    assert "PRIVATE KEY" not in download.text

    assert isinstance(client.get("/api/proxy/log?lines=10").json()["log"], str)


def test_exposing_the_dashboard_needs_an_account(client, engine):

    put(client, {"expose": True})

    # no accounts yet: the dashboard is open, so exposing it would be reckless
    refused = client.post("/api/proxy/start")

    assert refused.status_code == 400 and "create an account first" in refused.json()["detail"]

    put(client, {"expose": False})


# -- proxy mode for the dashboard itself -----------------------------------------------------------

def test_the_dashboard_can_be_restarted_in_proxy_mode(client, monkeypatch):

    api = client.api

    spawned = []

    monkeypatch.setattr(api.lifecycle, "original_command",
                        lambda: [sys.executable, "D:/IDS/serve.py", "--port", "8000"])

    monkeypatch.setattr(api.lifecycle, "spawn_relauncher", lambda command=None, **kw: spawned.append(command))

    # run the relaunch step directly instead of exiting the test process
    done = []

    monkeypatch.setattr(api.lifecycle, "restart", lambda spawn=None, **kw: (spawn and spawn(), done.append(True)))

    status = client.get("/api/proxy").json()

    assert status["can_switch_proxy_mode"] is True and status["dashboard_behind_proxy"] is False

    assert client.post("/api/server/restart", json={"behind_proxy": True}).json() == {"restarting": True}

    import time

    deadline = time.time() + 5

    while not done and time.time() < deadline:
        time.sleep(0.05)

    assert spawned and spawned[0][-1] == "--behind-proxy"
    assert spawned[0].count("--behind-proxy") == 1

    # switching it off removes the flag again
    monkeypatch.setattr(api.lifecycle, "original_command",
                        lambda: [sys.executable, "D:/IDS/serve.py", "--behind-proxy"])

    spawned.clear()
    done.clear()

    client.post("/api/server/restart", json={"behind_proxy": False})

    deadline = time.time() + 5

    while not done and time.time() < deadline:
        time.sleep(0.05)

    assert "--behind-proxy" not in spawned[0]


def test_proxy_mode_cannot_be_switched_for_a_server_not_started_with_serve_py(client, monkeypatch):

    monkeypatch.setattr(client.api.lifecycle, "original_command",
                        lambda: ["python", "-m", "uvicorn", "api:app"])

    response = client.post("/api/server/restart", json={"behind_proxy": True})

    assert response.status_code == 400 and "serve.py" in response.json()["detail"]


def test_the_upstream_address_comes_from_how_the_dashboard_was_started(client, monkeypatch):

    api = client.api

    for command, expected in [
        (["python", "serve.py"], "127.0.0.1:8000"),
        (["python", "serve.py", "--port", "9000"], "127.0.0.1:9000"),
        (["python", "serve.py", "--host", "0.0.0.0", "--port", "8123"], "127.0.0.1:8123"),
        (["python", "serve.py", "--host", "10.0.0.5"], "10.0.0.5:8000"),
    ]:
        monkeypatch.setattr(api.lifecycle, "original_command", lambda c=command: c)

        assert api.real_dashboard_upstream() == expected


# -- who may use it -----------------------------------------------------------------------------------

def test_only_admins_touch_the_proxy(client):

    ADMIN = [
        ("GET", "/api/proxy"), ("PUT", "/api/proxy/settings"), ("POST", "/api/proxy/install"),
        ("POST", "/api/proxy/start"), ("POST", "/api/proxy/stop"), ("POST", "/api/proxy/restart"),
        ("POST", "/api/proxy/test"), ("GET", "/api/proxy/log"),
        ("GET", "/api/proxy/certificate"), ("GET", "/api/proxy/certificate/download"),
    ]

    assert client.post("/api/users", json={"username": "root", "password": PASSWORD, "role": "admin"}).status_code == 200

    def token(name):
        return client.post("/api/login", json={"username": name, "password": PASSWORD}).json()["token"]

    root = {"Authorization": f"Bearer {token('root')}"}

    for name, role in (("vera", "viewer"), ("alan", "analyst")):
        client.post("/api/users", headers=root, json={"username": name, "password": PASSWORD, "role": role})

    for name in ("vera", "alan"):

        headers = {"Authorization": f"Bearer {token(name)}"}

        for method, path in ADMIN:
            response = client.request(method, path, headers=headers, json={} if method in ("POST", "PUT") else None)

            assert response.status_code == 403, f"{name} reached {method} {path}"

    for method, path in ADMIN:
        assert client.request(method, path).status_code == 401, f"{method} {path}"

    # an admin's proxy actions are in the audit trail
    audit = client.get("/api/audit?limit=200", headers=root).json()

    assert any(a["action"] == "PUT /api/proxy/settings" for a in audit)
    assert any(a["action"] == "POST /api/proxy/start" for a in audit)
