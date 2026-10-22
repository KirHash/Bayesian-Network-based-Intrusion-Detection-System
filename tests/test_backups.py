"""Backups: made, checked, restored; the login rate limit and the error handlers through the real API."""
import importlib
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

from backups import BackupError, BackupManager, check_file
from conftest import ROOT, needs_model
from storage import Store

PASSWORD = "correct horse battery"


@pytest.fixture
def store(tmp_path):

    store = Store(str(tmp_path / "ids.db"))

    store.add_user("root", "hash", "admin")
    store.add_audit("root", "something", "kept")

    yield store

    store.close()


@pytest.fixture
def manager(store, tmp_path):

    return BackupManager(store, str(tmp_path / "backups"), keep=2)


def test_a_backup_is_a_checked_copy_without_logins(store, manager):

    store.add_session("tokenhash", "root", "2999-01-01T00:00:00", "1.2.3.4")

    row = manager.create("manual")

    assert row["kind"] == "manual" and row["size"] > 0

    path = os.path.join(manager.directory, row["name"])

    assert check_file(path)["users"] == 1

    copy = sqlite3.connect(path)

    assert copy.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0

    copy.close()


def test_only_the_newest_automatic_backups_are_kept(manager):

    names = []

    for i in range(4):
        manager.clock = lambda i=i: 1_700_000_000 + i * 90_000
        names.append(manager.create("auto")["name"])

    kept = [r["name"] for r in manager.list() if r["kind"] == "auto"]

    assert sorted(kept) == sorted(names[2:])

    # manual ones are never pruned
    for i in range(3):
        manager.clock = lambda i=i: 1_800_000_000 + i
        manager.create("manual")

    assert len([r for r in manager.list() if r["kind"] == "manual"]) == 3


def test_a_daily_backup_is_made_only_when_due(manager):

    assert manager.due()

    manager.run_once()

    assert len(manager.list()) == 1 and not manager.due()

    manager.run_once()

    assert len(manager.list()) == 1


def test_a_failing_backup_is_remembered_not_raised(manager, monkeypatch):

    def broken(path):
        raise OSError("disk full")

    monkeypatch.setattr(manager.store, "backup_to", broken)

    manager.run_once()

    assert "disk full" in manager.last_error


def test_restore_brings_back_the_old_state_and_keeps_a_safety_copy(store, manager):

    row = manager.create("manual")

    store.add_user("mallory", "hash", "admin")
    store.add_session("old", "root", "2999-01-01T00:00:00", "1.1.1.1")

    assert store.get_user("mallory")

    result = manager.restore(row["name"])

    assert store.get_user("mallory") is None
    assert store.get_user("root")
    assert result["safety"].startswith("ids-before-restore-")

    # the replaced state is still there to go back to
    check_file(os.path.join(manager.directory, result["safety"]))

    # nobody stays signed in: a restore after a break-in must not keep old logins alive
    assert store.get_session("old") is None

    # and the database still works afterwards
    store.add_audit("root", "after", "ok")
    store.add_user("again", "hash", "viewer")


def test_restore_keeps_only_the_session_of_the_person_who_asked(store, manager):

    row = manager.create("manual")

    store.add_session("mine", "root", "2999-01-01T00:00:00", "1.1.1.1")
    store.add_session("theirs", "root", "2999-01-01T00:00:00", "9.9.9.9")

    manager.restore(row["name"], keep_session="mine")

    assert store.get_session("mine") and store.get_session("theirs") is None


def test_a_damaged_or_foreign_file_is_refused_before_anything_changes(store, manager, tmp_path):

    junk = tmp_path / "junk.db"
    junk.write_bytes(b"this is not a database at all" * 100)

    with pytest.raises(BackupError, match="not a readable database|cannot be opened"):
        check_file(str(junk))

    other = tmp_path / "other.db"
    db = sqlite3.connect(other)
    db.execute("CREATE TABLE unrelated (x)")
    db.commit()
    db.close()

    with pytest.raises(BackupError, match="not a backup of this program"):
        manager.add_upload(str(other))

    assert store.get_user("root")
    assert manager.list() == []


def test_names_cannot_reach_outside_the_backup_folder(manager):

    for name in ("../ids.db", "..\\ids.db", "ids-manual-20200101-000000.db/../../x", "other.db", ""):
        with pytest.raises(BackupError):
            manager.path(name)


# ---- through the real API ---------------------------------------------------------------------------

def admin(client, name="root"):

    token = client.post("/api/login", json={"username": name, "password": PASSWORD}).json()["token"]

    return {"Authorization": "Bearer " + token}


@pytest.fixture
def client(tmp_path, monkeypatch):

    monkeypatch.setenv("IDS_DB", str(tmp_path / "ids.db"))
    monkeypatch.setenv("IDS_DATA_DIR", str(tmp_path / "captures"))
    monkeypatch.setenv("IDS_MODEL", str(ROOT / "bayesian_ids.pkl"))

    for name in ("IDS_ADMIN_TOKEN", "IDS_API_KEY", "IDS_SECRET_KEY", "IDS_CORS_ORIGINS", "IDS_BACKUP_DIR"):
        monkeypatch.delenv(name, raising=False)

    monkeypatch.chdir(tmp_path)

    api = importlib.reload(importlib.import_module("api"))

    with TestClient(api.app, raise_server_exceptions=False) as client:

        client.api = api

        assert client.post("/api/users", json={"username": "root", "password": PASSWORD, "role": "admin"}).status_code == 200
        assert client.post("/api/users", headers=admin(client), json={"username": "vera", "password": PASSWORD, "role": "viewer"}).status_code == 200

        yield client


@needs_model
def test_backups_through_the_api_make_list_download_and_restore(client):

    headers = admin(client)

    made = client.post("/api/backups", headers=headers).json()

    assert made["kind"] == "manual"

    listing = client.get("/api/backups", headers=headers).json()

    assert [b["name"] for b in listing["backups"]] == [made["name"]]
    assert listing["keep"] >= 1

    download = client.get(f"/api/backups/{made['name']}", headers=headers)

    assert download.status_code == 200 and download.content.startswith(b"SQLite format 3")

    # an account made after the backup disappears with the restore
    assert client.post("/api/users", headers=headers, json={"username": "late", "password": PASSWORD, "role": "viewer"}).status_code == 200

    restored = client.post(f"/api/backups/{made['name']}/restore", headers=headers)

    assert restored.status_code == 200, restored.text
    assert restored.json()["safety"].startswith("ids-before-restore-")

    users = [u["username"] for u in client.get("/api/users", headers=headers).json()]

    assert "late" not in users and "root" in users

    # the administrator who restored is still signed in
    assert client.get("/api/auth", headers=headers).json()["ok"] is True

    # the restore is on the record
    audit = client.get("/api/audit", headers=headers).json()

    assert any("restore" in row["action"] for row in audit)


@needs_model
def test_uploading_a_backup_checks_it_and_a_bad_file_is_refused(client):

    headers = admin(client)

    made = client.post("/api/backups", headers=headers).json()

    good = client.get(f"/api/backups/{made['name']}", headers=headers).content

    uploaded = client.post("/api/backups/upload", headers=headers, content=good)

    assert uploaded.status_code == 200 and uploaded.json()["kind"] == "uploaded"

    refused = client.post("/api/backups/upload", headers=headers, content=b"not a database" * 50)

    assert refused.status_code == 400

    assert client.post("/api/backups/upload", headers=headers, content=b"").status_code == 400


@needs_model
def test_only_administrators_reach_backups(client):

    viewer = admin(client, "vera")

    for method, path in (("get", "/api/backups"), ("post", "/api/backups"), ("get", "/api/backups/x.db")):
        assert getattr(client, method)(path, headers=viewer).status_code == 403

    assert client.get("/api/backups").status_code == 401


@needs_model
def test_a_missing_or_odd_backup_name_is_a_clean_error(client):

    headers = admin(client)

    assert client.get("/api/backups/ids-manual-20200101-000000.db", headers=headers).status_code == 404
    assert client.post("/api/backups/nonsense/restore", headers=headers).status_code == 400


@needs_model
def test_signing_in_is_rate_limited_whatever_the_password(client):

    for _ in range(30):
        client.post("/api/login", json={"username": "nobody-" + os.urandom(3).hex(), "password": "wrong wrong wrong"})

    blocked = client.post("/api/login", json={"username": "root", "password": PASSWORD})

    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0
    assert "try again in" in blocked.json()["detail"]


@needs_model
def test_a_server_error_says_it_was_not_your_fault_and_gives_a_reference(client, caplog):

    headers = admin(client)

    def boom(*args, **kwargs):
        raise RuntimeError("secret internal detail")

    client.api.hub.store.stats = boom

    response = client.get("/api/stats", headers=headers)

    assert response.status_code == 500

    body = response.json()

    assert "Reference" in body["detail"] and body["reference"]
    assert "secret internal detail" not in response.text
    assert body["reference"] in caplog.text


@needs_model
def test_a_bad_request_gets_one_readable_sentence(client):

    response = client.post("/api/login", json={"username": "root"})

    assert response.status_code == 422
    assert isinstance(response.json()["detail"], str)
    assert "password" in response.json()["detail"]
