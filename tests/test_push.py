"""Push notifications: devices, the server's identity, what gets sent and to whom."""
import importlib
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

import webpush as wp
from conftest import ROOT, needs_model
from notifier import Notifier
from pushservice import MAX_DEVICES, PushService
from secrets_store import SecretBox
from storage import Store

PASSWORD = "correct horse battery"


def device(host="fcm.googleapis.com", n=1):
    """A browser's subscription (the keys are real points, so they pass the checks)."""

    private = ec.generate_private_key(ec.SECP256R1())

    return {
        "endpoint": f"https://{host}/send/{n}-{id(private)}",
        "keys": {"p256dh": wp.b64u(wp.point(private.public_key())), "auth": wp.b64u(b"0123456789abcdef")}
    }


class Fake:
    """Stands in for the push services: records what was sent, answers as told."""

    def __init__(self):
        self.sent = []
        self.answers = {}

    def __call__(self, subscription, payload, pem, public, subject):
        self.sent.append((subscription["endpoint"], json.loads(payload), subject))

        answer = self.answers.get(subscription["endpoint"], "sent")

        if isinstance(answer, Exception):
            raise answer

        return answer


@pytest.fixture
def store(tmp_path):

    store = Store(str(tmp_path / "p.db"))

    yield store

    store.close()


@pytest.fixture
def service(store, tmp_path):

    fake = Fake()

    service = PushService(store, box=SecretBox(tmp_path / "k.key"), sender=fake)

    service.fake = fake

    return service


# -- the server's identity ---------------------------------------------------------------------------------

def test_the_identity_is_made_once_kept_and_stored_encrypted(service, store):

    pem, public = service.keys()

    assert service.keys() == (pem, public) and service.public_key() == public

    assert len(wp.unb64u(public)) == 65

    stored = store.get_setting("push_vapid")

    assert stored["private"].startswith("enc:") and "PRIVATE KEY" not in stored["private"]
    assert stored["public"] == public


# -- devices ------------------------------------------------------------------------------------------------------

def test_a_person_adds_and_removes_devices(service):

    one, two = device(), device("updates.push.services.mozilla.com")

    assert service.subscribe("alice", one) == 1
    assert service.subscribe("alice", two) == 2

    # the same browser again is the same device
    assert service.subscribe("alice", one) == 2

    assert service.status("alice")["devices"] == 2 and service.status("bob")["devices"] == 0

    assert service.unsubscribe("alice", one["endpoint"]) == 1

    # nobody can remove someone else's device
    assert service.unsubscribe("bob", two["endpoint"]) == 0 and service.status("alice")["devices"] == 1


def test_a_device_cannot_be_registered_for_a_service_that_is_not_allowed(service):

    with pytest.raises(wp.PushError):
        service.subscribe("alice", device("internal.example.com"))

    assert service.status("alice")["devices"] == 0


def test_the_number_of_devices_is_capped(service):

    for i in range(MAX_DEVICES):
        service.subscribe("alice", device(n=i))

    with pytest.raises(wp.PushError, match="at most"):
        service.subscribe("alice", device(n=99))

    # re-registering one that exists is not a new device
    existing = service.store.list_push("alice")[0]

    service.subscribe("alice", {"endpoint": existing["endpoint"],
                                "keys": {"p256dh": existing["p256dh"], "auth": existing["auth"]}})


def test_devices_go_with_a_deleted_or_renamed_person(service, store):

    store.add_user("alice", "hash", "viewer")
    service.subscribe("alice", device())

    store.rename_user("alice", "alicia")

    assert service.status("alicia")["devices"] == 1 and service.status("alice")["devices"] == 0

    store.delete_user("alicia")

    assert store.list_push() == []


# -- sending ----------------------------------------------------------------------------------------------------------

def test_a_notification_reaches_every_device_and_says_who_the_server_is(service):

    service.subscribe("alice", device())
    service.subscribe("bob", device("updates.push.services.mozilla.com"))

    counts = service.notify("2 Critical alerts", "DDoS from 10.0.0.1", "/?alert=5")

    assert counts == {"sent": 2, "gone": 0, "failed": 0}

    endpoint, payload, subject = service.fake.sent[0]

    assert payload == {"title": "2 Critical alerts", "body": "DDoS from 10.0.0.1", "url": "/?alert=5", "tag": "ids"}
    assert subject.startswith("mailto:")


def test_it_can_be_aimed_at_people_or_at_a_role(service, store):

    store.add_user("root", "h", "admin")
    store.add_user("vera", "h", "viewer")

    service.subscribe("root", device())
    service.subscribe("vera", device())

    assert service.notify("t", "b", role="admin") == {"sent": 1, "gone": 0, "failed": 0}
    assert service.notify("t", "b", usernames=["vera"]) == {"sent": 1, "gone": 0, "failed": 0}
    assert service.notify("t", "b", usernames=["nobody"]) == {"sent": 0, "gone": 0, "failed": 0}

    store.update_user("root", disabled=1)

    assert service.notify("t", "b", role="admin")["sent"] == 0


def test_a_device_that_is_gone_is_forgotten_and_a_failure_does_not_stop_the_rest(service):

    good, gone, broken = device(n=1), device(n=2), device(n=3)

    for d in (good, gone, broken):
        service.subscribe("alice", d)

    service.fake.answers[gone["endpoint"]] = "gone"
    service.fake.answers[broken["endpoint"]] = wp.PushError("could not reach the push service")

    assert service.notify("t", "b") == {"sent": 1, "gone": 1, "failed": 1}

    # the gone one is not asked again; the failing one stays registered (it may be a passing outage)
    assert {s["endpoint"] for s in service.store.list_push("alice")} == {good["endpoint"], broken["endpoint"]}


def test_long_text_is_cut_to_fit(service):

    service.subscribe("alice", device())

    service.notify("T" * 500, "B" * 2000)

    payload = service.fake.sent[0][1]

    assert len(payload["title"]) == 100 and len(payload["body"]) == 300


# -- the notifier's side -----------------------------------------------------------------------------------------------

def alert(make_alert, id, risk="Critical", **kw):
    return {**make_alert(risk=risk, **kw), "id": id}


def test_critical_alerts_of_real_traffic_become_one_push_per_window(store, service, make_alert):

    service.subscribe("alice", device())

    notifier = Notifier(store, config={"window_seconds": 10, "min_risk": "High", "sources": ["capture"], "base_url": "http://x"})

    notifier.push = service

    notifier.submit([
        alert(make_alert, 1, probability=90.0), alert(make_alert, 2, probability=99.9, attack_type="PortScan", src_ip="10.9.9.9"),
        alert(make_alert, 3, risk="High"),                              # not Critical
        alert(make_alert, 4, source="replay"),                          # the demo never pushes
    ])

    assert [a["id"] for a in notifier.pending_push] == [1, 2]

    counts = notifier.send_push(notifier.pending_push)

    assert counts == {"sent": 1, "gone": 0, "failed": 0} and len(service.fake.sent) == 1

    payload = service.fake.sent[0][1]

    # one message for the window, linking to the worst alert
    assert payload["title"] == "2 Critical alerts" and payload["url"] == "/?alert=2"
    assert "DDoS" in payload["body"] and "PortScan" in payload["body"] and "10.9.9.9" in payload["body"]

    assert store.recent_notifications()[0]["channel"] == "push"


def test_nothing_is_queued_or_sent_without_a_push_service_or_devices(store, make_alert):

    notifier = Notifier(store, config={"window_seconds": 10, "min_risk": "High", "sources": ["capture"], "base_url": "x"})

    notifier.submit([alert(make_alert, 1)])

    assert notifier.pending_push == [] and notifier.send_push([alert(make_alert, 1)]) is None


def test_security_events_reach_administrators_devices_once_per_kind(store, service):

    store.add_user("root", "h", "admin")
    store.add_user("vera", "h", "viewer")

    service.subscribe("root", device())
    service.subscribe("vera", device())

    notifier = Notifier(store, config={"window_seconds": 10, "min_risk": "High", "sources": [], "base_url": "x"})

    notifier.push = service

    assert notifier.security("lockout", "5 failed attempts on user vera") is False     # no webhook / e-mail channel
    assert notifier.security_push("lockout", "again") is False                           # same kind, too soon

    deadline = time.time() + 5

    while not service.fake.sent and time.time() < deadline:
        time.sleep(0.02)

    assert len(service.fake.sent) == 1 and service.fake.sent[0][1]["title"] == "Security: lockout"


# -- through the API ----------------------------------------------------------------------------------------------------

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

        client.fake = Fake()

        api.hub.push.sender = client.fake

        yield client


@needs_model
def test_the_whole_flow_through_the_api(client):

    # open dashboard: devices belong to "local"
    status = client.get("/api/push").json()

    assert status["devices"] == 0 and len(wp.unb64u(status["public_key"])) == 65

    assert client.post("/api/push/test").status_code == 400          # nothing registered yet

    sub = device()

    assert client.post("/api/push/subscribe", json={"subscription": sub}).json() == {"devices": 1}

    assert client.post("/api/push/test").json() == {"sent": 1, "gone": 0, "failed": 0}
    assert client.fake.sent[0][1]["title"] == "Test notification"

    assert client.post("/api/push/unsubscribe", json={"endpoint": sub["endpoint"]}).json() == {"devices": 0}


@needs_model
def test_bad_subscriptions_are_refused(client):

    for bad in ({}, {"endpoint": "https://internal.example.com/x", "keys": {}}, device("evil.example.com")):
        assert client.post("/api/push/subscribe", json={"subscription": bad}).status_code == 400

    assert client.post("/api/push/subscribe", json={"nope": 1}).status_code == 422


@needs_model
def test_people_manage_only_their_own_devices_and_sign_in_is_needed(client):

    assert client.post("/api/users", json={"username": "root", "password": PASSWORD, "role": "admin"}).status_code == 200

    def sign_in(name):
        return {"Authorization": "Bearer " + client.post("/api/login", json={"username": name, "password": PASSWORD}).json()["token"]}

    root = sign_in("root")

    client.post("/api/users", headers=root, json={"username": "vera", "password": PASSWORD, "role": "viewer"})

    vera = sign_in("vera")

    assert client.get("/api/push").status_code == 401
    assert client.post("/api/push/subscribe", json={"subscription": device()}).status_code == 401

    # a viewer may register a device (it is a setting of their own), and sees only theirs
    mine = device()

    assert client.post("/api/push/subscribe", headers=vera, json={"subscription": mine}).status_code == 200
    assert client.get("/api/push", headers=vera).json()["devices"] == 1
    assert client.get("/api/push", headers=root).json()["devices"] == 0

    # another person's removal request does nothing to it
    client.post("/api/push/unsubscribe", headers=root, json={"endpoint": mine["endpoint"]})

    assert client.get("/api/push", headers=vera).json()["devices"] == 1


@needs_model
def test_a_critical_alert_from_the_api_reaches_a_device(client, make_alert):

    from test_model import scan_probe

    import pandas as pd

    client.post("/api/push/subscribe", json={"subscription": device()})

    notifier = client.api.hub.notifier

    assert client.post("/api/score?source=capture", json=pd.concat([scan_probe()] * 3, ignore_index=True).to_dict("records")).status_code == 200

    # the Critical alerts wait for the next window; the loop would send them, here it is done by hand
    assert notifier.pending_push and all(a["risk"] == "Critical" for a in notifier.pending_push)

    notifier.send_push(notifier.pending_push)

    assert len(client.fake.sent) == 1 and "Critical alert" in client.fake.sent[0][1]["title"]
    assert client.fake.sent[0][1]["url"].startswith("/?alert=")


def test_with_nobody_registered_nothing_is_started_and_no_key_is_made(store, service):

    notifier = Notifier(store, config={"window_seconds": 10, "min_risk": "High", "sources": [], "base_url": "x"})

    notifier.push = service

    assert notifier.security_push("lockout", "nobody to tell") is False
    assert service.notify("t", "b") == {"sent": 0, "gone": 0, "failed": 0}

    # no device, so no identity was generated either
    assert store.get_setting("push_vapid") is None


def test_a_failure_while_pushing_is_logged_not_raised(store, service, caplog):

    store.add_user("root", "h", "admin")
    service.subscribe("root", device())

    notifier = Notifier(store, config={"window_seconds": 10, "min_risk": "High", "sources": [], "base_url": "x"})

    notifier.push = service

    service.keys = lambda: (_ for _ in ()).throw(RuntimeError("the key is unreadable"))

    notifier.push_quietly("Security: lockout", "text")

    assert "a push notification could not be sent" in caplog.text
