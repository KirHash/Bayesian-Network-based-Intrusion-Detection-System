"""Two-factor sign-in, sessions, guess throttles and security alerts through the real API."""
import importlib
import time

import pytest
from fastapi.testclient import TestClient

from accounts import totp_at
from conftest import ROOT, needs_model
from throttle import Throttle

pytestmark = needs_model

PASSWORD = "correct horse battery"

# the server's clock can be moved forward, so a code spent a moment ago is not the only one on offer
OFFSET = [0.0]


def now():
    return time.time() + OFFSET[0]


def advance(client, seconds=31):
    """Let the next 30-second step begin."""

    OFFSET[0] += seconds
    client.api.hub.accounts.clock = now


@pytest.fixture
def client(tmp_path, monkeypatch):

    monkeypatch.setenv("IDS_DB", str(tmp_path / "ids.db"))
    monkeypatch.setenv("IDS_DATA_DIR", str(tmp_path / "captures"))
    monkeypatch.setenv("IDS_MODEL", str(ROOT / "bayesian_ids.pkl"))

    for name in ("IDS_ADMIN_TOKEN", "IDS_API_KEY", "IDS_SECRET_KEY", "IDS_CORS_ORIGINS"):
        monkeypatch.delenv(name, raising=False)

    monkeypatch.chdir(tmp_path)

    api = importlib.reload(importlib.import_module("api"))

    OFFSET[0] = 0.0

    with TestClient(api.app) as client:

        client.api = api

        assert client.post("/api/users", json={"username": "root", "password": PASSWORD, "role": "admin"}).status_code == 200
        assert client.post("/api/users", headers=login(client), json={"username": "vera", "password": PASSWORD, "role": "viewer"}).status_code == 200

        yield client


def login(client, name="root", code=None, password=PASSWORD):

    body = {"username": name, "password": password, **({"code": code} if code else {})}

    response = client.post("/api/login", json=body)

    return {"Authorization": "Bearer " + response.json()["token"]} if response.status_code == 200 else response


def current_code(secret, ahead=0):
    return totp_at(secret, int(now() // 30) + ahead)


def enable(client, name="root"):
    """Turn two-factor on for a person; returns (secret, recovery codes)."""

    headers = login(client, name)

    started = client.post("/api/account/two-factor/start", headers=headers, json={"current_password": PASSWORD}).json()

    confirmed = client.post("/api/account/two-factor/confirm", headers=headers, json={"code": current_code(started["secret"])})

    assert confirmed.status_code == 200, confirmed.text

    return started["secret"], confirmed.json()["recovery_codes"]


# -- the whole story ----------------------------------------------------------------------------------------------

def test_setting_it_up_then_signing_in_with_a_code(client):

    headers = login(client)

    assert client.get("/api/account/two-factor", headers=headers).json() == {"enabled": False, "recovery_left": 0}

    # the password is asked again before a secret is made
    refused = client.post("/api/account/two-factor/start", headers=headers, json={"current_password": "not the password"})

    assert refused.status_code == 400

    started = client.post("/api/account/two-factor/start", headers=headers, json={"current_password": PASSWORD}).json()

    assert started["uri"].startswith("otpauth://totp/") and started["secret"] in started["uri"]

    # it is not on until a code from the secret is shown to work
    assert login(client) != None and isinstance(login(client), dict)

    wrong = client.post("/api/account/two-factor/confirm", headers=headers, json={"code": "000000"})

    assert wrong.status_code == 400

    confirmed = client.post("/api/account/two-factor/confirm", headers=headers, json={"code": current_code(started["secret"])})

    codes = confirmed.json()["recovery_codes"]

    assert len(codes) == 8 and client.get("/api/account/two-factor", headers=headers).json()["enabled"] is True

    # a password alone now gets only "enter the code", and no session
    asked = login(client)

    assert asked.status_code == 401 and asked.json()["two_factor"] is True and "token" not in asked.json()

    # a wrong password never reveals the second factor
    assert "two_factor" not in login(client, password="not the password").json()

    # the confirming code is spent; the next step's is accepted
    reused = login(client, code=current_code(started["secret"]))

    assert reused.status_code == 401

    advance(client)

    ok = login(client, code=current_code(started["secret"]))

    assert "Authorization" in ok and client.get("/api/account", headers=ok).json()["two_factor"] is True


def test_recovery_codes_and_the_admin_reset(client):

    secret, codes = enable(client)

    ok = login(client, code=codes[0])

    assert "Authorization" in ok and client.get("/api/account/two-factor", headers=ok).json()["recovery_left"] == 7

    assert login(client, code=codes[0]).status_code == 401           # spent

    # a second admin cannot read the secret, only reset it
    users = {u["username"]: u for u in client.get("/api/users", headers=ok).json()}

    assert users["root"]["two_factor"] is True
    assert not ({"totp_secret", "recovery", "password_hash", "totp_step"} & set(users["root"]))

    assert client.patch("/api/users/root", headers=ok, json={"reset_two_factor": True}).status_code == 200

    assert "Authorization" in login(client)


def test_turning_it_off_needs_the_password_and_a_code(client):

    secret, _ = enable(client)

    advance(client)

    headers = login(client, code=current_code(secret))

    advance(client)

    assert client.post("/api/account/two-factor/disable", headers=headers,
                       json={"current_password": PASSWORD, "code": "000000"}).status_code == 400

    assert client.post("/api/account/two-factor/disable", headers=headers,
                       json={"current_password": "not the password", "code": current_code(secret)}).status_code == 400

    done = client.post("/api/account/two-factor/disable", headers=headers,
                       json={"current_password": PASSWORD, "code": current_code(secret)})

    assert done.status_code == 200 and "Authorization" in login(client)


def test_changing_the_password_with_two_factor_on_asks_for_the_code(client):

    secret, _ = enable(client)

    advance(client)

    headers = login(client, code=current_code(secret))

    asked = client.patch("/api/account", headers=headers, json={"current_password": PASSWORD, "new_password": "a different long password"})

    # a 400, not a 401: the person is signed in and must not be thrown out of the page
    assert asked.status_code == 400 and asked.json()["two_factor"] is True

    advance(client)

    done = client.patch("/api/account", headers=headers, json={
        "current_password": PASSWORD, "new_password": "a different long password", "code": current_code(secret)})

    assert done.status_code == 200 and "token" in done.json()


def test_the_secret_is_not_in_any_answer_or_the_audit_trail(client):

    secret, codes = enable(client)

    advance(client)

    headers = login(client, code=current_code(secret))

    everything = " ".join([
        client.get("/api/users", headers=headers).text, client.get("/api/audit?limit=200", headers=headers).text,
        client.get("/api/logs?limit=500", headers=headers).text, client.get("/api/account", headers=headers).text,
    ])

    assert secret not in everything and not any(c in everything for c in codes)

    # only the encrypted form is in the database
    stored = client.api.hub.store.get_user("root")["totp_secret"]

    assert stored.startswith("enc:") and secret not in stored


# -- sessions --------------------------------------------------------------------------------------------------------

def test_people_see_and_end_their_other_sessions(client):

    mine = login(client)
    login(client)
    login(client)

    listed = client.get("/api/account/sessions", headers=mine).json()

    assert len(listed) >= 3 and [s["current"] for s in listed].count(True) == 1
    assert all("token" not in s and len(s["id"]) == 12 for s in listed)

    ended = client.post("/api/account/sessions/sign-out-others", headers=mine).json()["ended"]

    assert ended >= 2 and len(client.get("/api/account/sessions", headers=mine).json()) == 1


def test_account_pages_are_for_named_accounts_only(client):

    assert client.get("/api/account/two-factor").status_code == 401

    for path in ("/api/account/sessions",):
        assert client.get(path).status_code == 401


# -- guesses are throttled and reported --------------------------------------------------------------------------

def test_the_throttle_blocks_after_the_limit_and_forgets(monkeypatch):

    now = [1000.0]

    throttle = Throttle(limit=3, window=60, clock=lambda: now[0])

    assert [throttle.fail("a"), throttle.fail("a"), throttle.fail("a")] == [False, False, True]

    assert throttle.blocked("a") > 0 and throttle.blocked("b") == 0

    now[0] += 61

    assert throttle.blocked("a") == 0


def test_guessing_access_tokens_gets_an_address_blocked_and_reported(client):

    api = client.api

    seen = []

    api.hub.notifier.security = lambda kind, text, every=300: seen.append((kind, text))

    for _ in range(30):
        assert client.get("/api/stats", headers={"Authorization": "Bearer wrong"}).status_code == 401

    blocked = client.get("/api/stats", headers={"Authorization": "Bearer wrong"})

    assert blocked.status_code == 429 and "Retry-After" in blocked.headers

    assert [k for k, _ in seen] == ["token guessing"]

    # even a right token waits out the block from that address: the point of a block
    assert client.get("/api/stats", headers=login(client)).status_code == 429


def test_requests_with_no_token_are_not_guesses(client):

    for _ in range(40):
        assert client.get("/api/stats").status_code == 401

    assert "Authorization" in login(client)


def test_a_lockout_reaches_the_audit_trail_and_the_notification_channels(client):

    api = client.api

    sent = []

    # signed in before the address gets locked out
    root = login(client, "root")

    api.hub.notifier.channels = lambda: ["webhook"]
    api.hub.notifier.deliver = lambda subject, text, count: sent.append((subject, text))

    for _ in range(5):
        client.post("/api/login", json={"username": "vera", "password": "wrong password"})

    deadline = time.time() + 5

    while not sent and time.time() < deadline:
        time.sleep(0.05)

    assert sent and sent[0][0] == "Security: lockout" and "vera" in sent[0][1]

    # and it is in the audit trail for admins
    audit = client.get("/api/audit?limit=100", headers=root).json()

    assert any(a["action"] == "security: lockout" for a in audit)


def test_security_messages_are_rate_limited_per_kind(client):

    notifier = client.api.hub.notifier

    sent = []

    notifier.channels = lambda: ["webhook"]
    notifier.deliver = lambda subject, text, count: sent.append(subject)

    assert notifier.security("lockout", "first") is True
    assert notifier.security("lockout", "second") is False            # same kind, too soon
    assert notifier.security("two-factor", "other kind") is True

    deadline = time.time() + 5

    while len(sent) < 2 and time.time() < deadline:
        time.sleep(0.05)

    assert sorted(sent) == ["Security: lockout", "Security: two-factor"]


def test_no_channel_means_no_message_and_no_error(client):

    assert client.api.hub.notifier.security("lockout", "nobody to tell") is False


# -- headers ------------------------------------------------------------------------------------------------------------

def test_api_answers_are_not_cached_and_carry_the_extra_headers(client):

    response = client.get("/api/healthz")

    assert response.headers["Cache-Control"] == "no-store"
    assert "camera=()" in response.headers["Permissions-Policy"]
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
