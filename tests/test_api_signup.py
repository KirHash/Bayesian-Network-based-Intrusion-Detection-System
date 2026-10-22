"""Self-registration: the first account, approval, and what it must never allow."""
import importlib

import pytest
from fastapi.testclient import TestClient

from accounts import AccountError, Accounts, Locked
from conftest import needs_model
from storage import Store

PASSWORD = "correct horse battery"


# -- the rules, without a server ------------------------------------------------------------------

@pytest.fixture
def acc(tmp_path):

    store = Store(str(tmp_path / "s.db"))

    yield Accounts(store)

    store.close()


def test_the_first_account_is_the_administrator(acc):

    assert acc.signup_state() == "first"

    assert acc.signup("alice", PASSWORD) == ("alice", "admin", False)

    # and the door closes behind it
    assert acc.signup_state() == "closed"

    with pytest.raises(AccountError, match="closed"):
        acc.signup("mallory", PASSWORD)


def test_with_an_admin_token_nobody_can_claim_the_first_account(acc):

    assert acc.signup_state(token_required=True) == "closed"

    with pytest.raises(AccountError, match="closed"):
        acc.signup("mallory", PASSWORD, token_required=True)

    assert not acc.any_users()


def test_after_approval_mode_is_switched_on_new_accounts_wait(acc):

    acc.signup("alice", PASSWORD)

    acc.set_signup_mode("approval")

    assert acc.signup_state() == "approval"

    assert acc.signup("bob", PASSWORD) == ("bob", "viewer", True)

    # cannot sign in yet, and is told why only when the password is right
    with pytest.raises(AccountError, match="waiting for an administrator"):
        acc.login("bob", PASSWORD)

    with pytest.raises(AccountError, match="wrong username or password"):
        acc.login("bob", "not the password")

    acc.set_disabled("bob", False)

    token, user = acc.login("bob", PASSWORD)

    assert user["role"] == "viewer" and acc.resolve(token)


def test_signup_is_validated_like_any_account(acc):

    acc.signup("alice", PASSWORD)
    acc.set_signup_mode("approval")

    with pytest.raises(AccountError, match="at least"):
        acc.signup("bob", "short")

    with pytest.raises(AccountError, match="usernames are"):
        acc.signup("!", PASSWORD)

    with pytest.raises(AccountError, match="taken"):
        acc.signup("alice", PASSWORD)


def test_signups_are_rate_limited_per_address(acc):

    acc.signup("alice", PASSWORD)
    acc.set_signup_mode("approval")

    for i in range(Accounts.SIGNUP_PER_HOUR):
        acc.signup(f"user{i}", PASSWORD, client="1.2.3.4")

    with pytest.raises(Locked):
        acc.signup("one-too-many", PASSWORD, client="1.2.3.4")

    # a different address is unaffected
    acc.signup("other", PASSWORD, client="5.6.7.8")


def test_the_mode_can_only_be_off_or_approval(acc):

    with pytest.raises(AccountError):
        acc.set_signup_mode("open")

    assert acc.signup_mode() == "off"


# -- through the API ---------------------------------------------------------------------------------

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


@needs_model
def test_the_whole_story_through_the_api(client):

    # a fresh server offers to create the first administrator
    assert client.get("/api/auth").json()["signup"] == "first"

    first = client.post("/api/signup", json={"username": "Alice", "password": PASSWORD}).json()

    assert first["role"] == "admin" and first["pending"] is False and first["token"]

    admin = headers(first["token"])

    # signed in straight away, and sign-up is now closed to the public
    assert client.get("/api/account", headers=admin).json()["username"] == "alice"
    assert client.get("/api/auth").json()["signup"] == "closed"
    assert client.post("/api/signup", json={"username": "bob", "password": PASSWORD}).status_code == 400

    # only an admin can open it
    assert client.get("/api/signup-policy").status_code == 401
    assert client.put("/api/signup-policy", json={"mode": "approval"}).status_code == 401

    assert client.put("/api/signup-policy", headers=admin, json={"mode": "open"}).status_code == 400
    assert client.put("/api/signup-policy", headers=admin, json={"mode": "approval"}).json() == {"mode": "approval"}

    assert client.get("/api/auth").json()["signup"] == "approval"

    # a stranger signs up: pending, not signed in
    bob = client.post("/api/signup", json={"username": "bob", "password": PASSWORD}).json()

    assert bob == {"username": "bob", "role": "viewer", "pending": True}

    tried = client.post("/api/login", json={"username": "bob", "password": PASSWORD})

    assert tried.status_code == 401 and "waiting" in tried.json()["detail"]

    # the admin sees the pending account and approves it
    listed = {u["username"]: u for u in client.get("/api/users", headers=admin).json()}

    assert listed["bob"]["disabled"] == 2

    assert client.patch("/api/users/bob", headers=admin, json={"disabled": False}).status_code == 200

    assert client.post("/api/login", json={"username": "bob", "password": PASSWORD}).status_code == 200

    # a viewer cannot change the policy
    token = client.post("/api/login", json={"username": "bob", "password": PASSWORD}).json()["token"]

    assert client.put("/api/signup-policy", headers=headers(token), json={"mode": "off"}).status_code == 403

    # sign-ups are audited, without passwords
    audit = client.get("/api/audit?limit=50", headers=admin).json()

    assert any(a["action"] == "signup" for a in audit) and PASSWORD not in str(audit)


@needs_model
def test_a_server_protected_by_a_token_never_offers_the_first_account(client, monkeypatch):

    monkeypatch.setenv("IDS_ADMIN_TOKEN", "t" * 24)

    assert client.get("/api/auth").json()["signup"] == "closed"

    assert client.post("/api/signup", json={"username": "mallory", "password": PASSWORD}).status_code == 400
