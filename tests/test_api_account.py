"""People changing their own username and password through the API."""
import importlib

import pytest
from fastapi.testclient import TestClient

from conftest import needs_model

pytestmark = needs_model

PASSWORD = "correct horse battery"
NEW = "another long password"


@pytest.fixture
def client(tmp_path, monkeypatch):

    monkeypatch.setenv("IDS_DB", str(tmp_path / "ids.db"))
    monkeypatch.setenv("IDS_DATA_DIR", str(tmp_path / "captures"))

    for name in ("IDS_ADMIN_TOKEN", "IDS_API_KEY", "IDS_SECRET_KEY", "IDS_CORS_ORIGINS"):
        monkeypatch.delenv(name, raising=False)

    monkeypatch.chdir(tmp_path)

    api = importlib.reload(importlib.import_module("api"))

    with TestClient(api.app) as client:
        yield client


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def sign_in(client, name, password=PASSWORD):

    response = client.post("/api/login", json={"username": name, "password": password})

    return response.json()["token"] if response.status_code == 200 else None


@pytest.fixture
def people(client):

    assert client.post("/api/users", json={"username": "root", "password": PASSWORD, "role": "admin"}).status_code == 200

    root = headers(sign_in(client, "root"))

    for name, role in (("vera", "viewer"), ("alan", "analyst")):
        client.post("/api/users", headers=root, json={"username": name, "password": PASSWORD, "role": role})

    return client


@pytest.mark.parametrize("name", ["root", "alan", "vera"])
def test_every_role_sees_and_changes_its_own_account(people, name):

    token = sign_in(people, name)

    mine = people.get("/api/account", headers=headers(token)).json()

    assert mine["username"] == name and mine["editable"] is True

    done = people.patch("/api/account", headers=headers(token), json={
        "current_password": PASSWORD, "new_username": f"{name}2", "new_password": NEW})

    assert done.status_code == 200 and done.json()["username"] == f"{name}2"

    # the old session ended, the returned one works, and only the new credentials sign in
    assert people.get("/api/account", headers=headers(token)).status_code == 401

    fresh = headers(done.json()["token"])

    assert people.get("/api/account", headers=fresh).json()["username"] == f"{name}2"
    assert sign_in(people, name) is None and sign_in(people, name + "2") is None
    assert sign_in(people, name + "2", NEW)


def test_the_role_survives_a_rename(people):

    token = sign_in(people, "alan")

    done = people.patch("/api/account", headers=headers(token),
                        json={"current_password": PASSWORD, "new_username": "alan.b"}).json()

    assert done["role"] == "analyst"
    assert people.get("/api/account", headers=headers(done["token"])).json()["role"] == "analyst"


def test_the_current_password_is_required_and_checked(people):

    token = headers(sign_in(people, "vera"))

    missing = people.patch("/api/account", headers=token, json={"new_password": NEW})

    assert missing.status_code == 422

    wrong = people.patch("/api/account", headers=token, json={"current_password": "nope-nope-nope", "new_password": NEW})

    assert wrong.status_code == 400 and "current password is wrong" in wrong.json()["detail"]
    assert sign_in(people, "vera")


def test_bad_requests_are_explained(people):

    token = headers(sign_in(people, "vera"))

    for body, message in [
        ({"new_password": "short"}, "at least"),
        ({"new_username": "root"}, "taken"),
        ({"new_username": "!!"}, "usernames are"),
        ({}, "nothing to change"),
    ]:
        response = people.patch("/api/account", headers=token, json={"current_password": PASSWORD, **body})

        assert response.status_code == 400 and message in response.json()["detail"], body


def test_guessing_the_current_password_locks_out_like_signing_in(people):

    token = headers(sign_in(people, "vera"))

    codes = [
        people.patch("/api/account", headers=token,
                     json={"current_password": f"guess-guess-{i}", "new_password": NEW}).status_code
        for i in range(8)
    ]

    assert 429 in codes


def test_it_needs_a_signed_in_person_and_is_audited_without_passwords(people):

    assert people.get("/api/account").status_code == 401
    assert people.patch("/api/account", json={"current_password": "x"}).status_code == 401

    root = headers(sign_in(people, "root"))

    token = headers(sign_in(people, "vera"))

    people.patch("/api/account", headers=token, json={"current_password": PASSWORD, "new_password": NEW})

    audit = people.get("/api/audit?limit=50", headers=root).json()

    line = next(a for a in audit if a["action"] == "PATCH /api/account")

    assert "password" in line["detail"] and NEW not in str(audit) and PASSWORD not in str(audit)


def test_open_mode_and_the_admin_token_have_nothing_to_edit(client):

    mine = client.get("/api/account").json()

    assert mine["editable"] is False and mine["via"] == "open"

    assert client.patch("/api/account", json={"current_password": "x", "new_password": NEW}).status_code == 400


def test_start_at_login_starts_the_whole_online_setup_when_it_was_started_by_the_launcher(client, monkeypatch):

    import api_core as api

    monkeypatch.delenv("IDS_LAUNCHER", raising=False)

    assert api.launcher_command() is None

    monkeypatch.setenv("IDS_LAUNCHER", "go_online")

    command = api.launcher_command()

    assert command[-2].endswith("go_online.py") and command[-1] == "--no-browser"
