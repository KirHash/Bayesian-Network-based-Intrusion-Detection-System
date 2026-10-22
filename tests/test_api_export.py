"""Exporting the alerts table as CSV."""
import csv
import importlib
import io
import re

import pytest
from fastapi.testclient import TestClient

from conftest import ROOT, needs_model

pytestmark = needs_model

PASSWORD = "correct horse battery"


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

        yield client


def rows_of(response):

    return list(csv.DictReader(io.StringIO(response.text)))


@pytest.fixture
def alerts(client, make_alert):

    client.api.hub.store.add_alerts([
        make_alert(attack_type="DDoS", risk="Critical", src_ip="10.0.0.1"),
        make_alert(attack_type="PortScan", risk="High", src_ip="10.0.0.2", source="api"),
        make_alert(attack_type="DDoS", risk="Medium", src_ip="@attacker", dst_ip="=1+1"),
        make_alert(attack_type="Bot", risk="High", src_ip="10.0.0.4"),
    ])

    client.api.hub.store.update_alert(1, status="resolved", note='=HYPERLINK("http://evil","click")')

    return client


def test_the_export_is_a_csv_file_with_every_column_newest_first(alerts):

    response = alerts.get("/api/alerts/export")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert re.fullmatch(r'attachment; filename="alerts-\d{8}-\d{6}\.csv"', response.headers["content-disposition"])
    assert response.headers["cache-control"] == "no-store"

    rows = rows_of(response)

    assert [r["id"] for r in rows] == ["4", "3", "2", "1"]
    assert list(rows[0]) == [
        "id", "time", "source", "attack_type", "reason", "risk", "probability", "surprise", "label",
        "src_ip", "dst_ip", "dst_port", "status", "assignee", "note", "updated_at"
    ]
    assert rows[3]["status"] == "resolved" and rows[0]["src_ip"] == "10.0.0.4"


def test_it_uses_the_same_filters_as_the_table(alerts):

    assert [r["id"] for r in rows_of(alerts.get("/api/alerts/export?attack_type=DDoS"))] == ["3", "1"]
    assert [r["id"] for r in rows_of(alerts.get("/api/alerts/export?risk=High"))] == ["4", "2"]
    assert [r["id"] for r in rows_of(alerts.get("/api/alerts/export?source=api"))] == ["2"]
    assert [r["id"] for r in rows_of(alerts.get("/api/alerts/export?status=resolved"))] == ["1"]
    assert [r["id"] for r in rows_of(alerts.get("/api/alerts/export?status=open&risk=High"))] == ["4", "2"]
    assert [r["id"] for r in rows_of(alerts.get("/api/alerts/export?q=10.0.0.2"))] == ["2"]
    assert rows_of(alerts.get("/api/alerts/export?attack_type=Nothing")) == []


def test_text_that_would_run_as_a_formula_is_defused(alerts):

    rows = {r["id"]: r for r in rows_of(alerts.get("/api/alerts/export"))}

    assert rows["1"]["note"] == "'=HYPERLINK(\"http://evil\",\"click\")"
    assert rows["3"]["src_ip"] == "'@attacker" and rows["3"]["dst_ip"] == "'=1+1"

    # ordinary values are untouched
    assert rows["2"]["src_ip"] == "10.0.0.2" and rows["2"]["dst_port"] == "80"


def test_the_limit_caps_the_rows_and_pages_do_not_repeat_or_skip(client, make_alert):

    client.api.hub.store.add_alerts([make_alert(src_ip=f"10.1.{i // 250}.{i % 250}") for i in range(2300)])

    everything = [r["id"] for r in rows_of(client.get("/api/alerts/export"))]

    # three pages of 1000, 1000 and 300, newest first, each once
    assert len(everything) == 2300 and len(set(everything)) == 2300
    assert everything == [str(i) for i in range(2300, 0, -1)]

    assert len(rows_of(client.get("/api/alerts/export?limit=1500"))) == 1500
    assert client.get("/api/alerts/export?limit=0").status_code == 422
    assert client.get("/api/alerts/export?limit=100001").status_code == 422


def test_an_empty_table_still_gives_the_header(client):

    assert client.get("/api/alerts/export").text.splitlines() == [
        "id,time,source,attack_type,reason,risk,probability,surprise,label,src_ip,dst_ip,dst_port,status,assignee,note,updated_at"
    ]


def test_an_export_is_in_the_audit_trail_with_its_filters(alerts):

    assert alerts.post("/api/users", json={"username": "root", "password": PASSWORD, "role": "admin"}).status_code == 200

    token = alerts.post("/api/login", json={"username": "root", "password": PASSWORD}).json()["token"]

    headers = {"Authorization": f"Bearer {token}"}

    assert alerts.get("/api/alerts/export?risk=High&attack_type=Bot", headers=headers).status_code == 200

    audit = alerts.get("/api/audit?limit=20", headers=headers).json()

    line = next(a for a in audit if a["action"] == "export alerts")

    assert line["actor"] == "root" and "risk=High" in line["detail"] and "attack_type=Bot" in line["detail"]


def test_only_signed_in_people_may_export_and_viewers_may(alerts):

    assert alerts.post("/api/users", json={"username": "root", "password": PASSWORD, "role": "admin"}).status_code == 200

    def sign_in(name):
        return {"Authorization": "Bearer " + alerts.post("/api/login", json={"username": name, "password": PASSWORD}).json()["token"]}

    root = sign_in("root")

    alerts.post("/api/users", headers=root, json={"username": "vera", "password": PASSWORD, "role": "viewer"})

    assert alerts.get("/api/alerts/export").status_code == 401
    assert alerts.get("/api/alerts/export", headers=sign_in("vera")).status_code == 200


# -- address lookups ---------------------------------------------------------------------------------------------

import socket

import pytest as _pytest

import routes.alerts as alert_routes


@_pytest.mark.parametrize("address, kind", [
    ("10.1.2.3", "private"), ("192.168.0.9", "private"), ("172.16.5.5", "private"), ("fd00::1", "private"),
    ("127.0.0.1", "loopback"), ("::1", "loopback"), ("169.254.1.1", "link-local"), ("fe80::1", "link-local"),
    ("239.255.255.250", "multicast"), ("ff02::fb", "multicast"), ("0.0.0.0", "reserved"),
    ("8.8.8.8", "public"), ("2606:4700:4700::1111", "public"), ("172.32.0.1", "public"),
])
def test_what_kind_of_address(address, kind):

    assert alert_routes.ip_kind(address) == kind


def test_only_public_addresses_are_looked_up_and_the_answer_is_remembered(client, monkeypatch):

    asked = []

    def fake(address):
        asked.append(address)
        return ("dns.google", [], [address])

    monkeypatch.setattr(socket, "gethostbyaddr", fake)
    monkeypatch.setattr(alert_routes, "name_cache", {})

    assert client.get("/api/lookup/8.8.8.8").json() == {"address": "8.8.8.8", "kind": "public", "name": "dns.google"}

    client.get("/api/lookup/8.8.8.8")

    assert asked == ["8.8.8.8"]                      # the second answer came from memory

    # private, loopback and multicast addresses never reach a resolver
    for address in ("10.0.0.5", "127.0.0.1", "239.255.255.250"):
        assert client.get(f"/api/lookup/{address}").json()["name"] is None

    assert asked == ["8.8.8.8"]


def test_a_failing_or_slow_resolver_gives_no_name_not_an_error(client, monkeypatch):

    monkeypatch.setattr(alert_routes, "name_cache", {})

    def refuse(address):
        raise socket.herror(1, "Unknown host")

    monkeypatch.setattr(socket, "gethostbyaddr", refuse)

    assert client.get("/api/lookup/9.9.9.9").json()["name"] is None

    import time

    def slow(address):
        time.sleep(0.5)
        return ("late.example", [], [address])

    monkeypatch.setattr(socket, "gethostbyaddr", slow)
    monkeypatch.setattr(alert_routes, "LOOKUP_SECONDS", 0.05)

    assert client.get("/api/lookup/1.0.0.1").json() == {"address": "1.0.0.1", "kind": "public", "name": None}


def test_something_that_is_not_an_address_is_refused(client):

    for bad in ("not-an-ip", "8.8.8", "8.8.8.8.8"):
        assert client.get(f"/api/lookup/{bad}").status_code == 400

    # an address that does not match any endpoint is a JSON 404, not the dashboard's page
    missing = client.get("/api/lookup/1.1.1.1%2Fetc")

    assert missing.status_code == 404 and missing.json()["detail"] == "no such API endpoint"
    assert client.get("/api/nothing-here").status_code == 404

    assert client.get("/api/lookup/not-an-ip").json()["detail"] == "that is not an IP address"


def test_lookups_need_a_sign_in(client):

    assert client.post("/api/users", json={"username": "root", "password": PASSWORD, "role": "admin"}).status_code == 200

    assert client.get("/api/lookup/8.8.8.8").status_code == 401


# -- how drift moved over time ----------------------------------------------------------------------------------------

def test_the_drift_history_gets_a_point_every_few_seconds_not_every_batch(client):

    import api_core

    hub = client.api.hub

    report = {"status": "stable", "max_psi": 0.12, "anomaly_rate": 0.004}

    assert api_core.record_drift("replay", report, now=1000.0) is True
    assert api_core.record_drift("replay", report, now=1003.0) is False        # too soon
    assert api_core.record_drift("replay", {**report, "status": "drift", "max_psi": 0.9}, now=1011.0) is True

    points = client.get("/api/drift/history?source=replay").json()["replay"]

    assert [(p["status"], p["max_psi"]) for p in points] == [("stable", 0.12), ("drift", 0.9)]
    assert all(set(p) == {"at", "t", "status", "max_psi", "anomaly_rate"} for p in points)

    # per source, and only what was asked for
    assert client.get("/api/drift/history?source=api").json() == {"api": []}
    assert set(client.get("/api/drift/history").json()) == {"capture", "api", "replay"}

    # a report that has no numbers yet (still warming up) is still a point
    assert api_core.record_drift("api", {"status": "warming up"}, now=2000.0) is True

    assert client.get("/api/drift/history?source=api").json()["api"][0]["max_psi"] is None

    # clearing a source's demo data clears its history
    hub.reset_live("replay")

    assert client.get("/api/drift/history?source=replay").json() == {"replay": []}


def test_the_history_is_bounded(client):

    import api_core

    for i in range(api_core.DRIFT_POINTS + 50):
        api_core.record_drift("api", {"status": "stable"}, now=10_000.0 + i * 20)

    assert len(client.get("/api/drift/history?source=api").json()["api"]) == api_core.DRIFT_POINTS


def test_scoring_flows_records_the_drift(client, monkeypatch):

    from test_model import flows

    import pandas as pd

    rows = pd.concat([flows()] * 40, ignore_index=True).to_dict("records")

    assert client.post("/api/score", json=rows).status_code == 200

    points = client.get("/api/drift/history?source=api").json()["api"]

    assert len(points) == 1 and points[0]["status"] in ("stable", "warming up", "warning", "drift")

    # a second batch straight after adds no point
    client.post("/api/score", json=rows)

    assert len(client.get("/api/drift/history?source=api").json()["api"]) == 1
