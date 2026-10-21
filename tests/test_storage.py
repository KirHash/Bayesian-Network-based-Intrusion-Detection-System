import pytest

from storage import Store


@pytest.fixture
def store(tmp_path):

    store = Store(str(tmp_path / "test.db"))

    yield store

    store.close()


def test_alerts_get_sequential_ids_and_round_trip(store, make_alert):

    ids = store.add_alerts([make_alert(), make_alert(attack_type="PortScan")])

    assert ids == [1, 2]

    alert = store.get_alert(2)

    assert alert["attack_type"] == "PortScan"
    assert alert["status"] == "new"
    assert alert["posterior"]["DDoS"] == 0.995
    assert alert["features"] == {"Destination Port": 80.0}
    assert alert["events"] == []

    assert store.add_alerts([make_alert()]) == [3]


def test_unknown_alert_is_none(store):

    assert store.get_alert(99) is None
    assert store.update_alert(99, status="resolved") is None


def test_status_change_is_recorded_in_history(store, make_alert):

    store.add_alerts([make_alert()])

    alert = store.update_alert(
        1, status="investigating", assignee="sam", note="looking", actor="kim"
    )

    assert alert["status"] == "investigating"
    assert alert["assignee"] == "sam"
    assert alert["note"] == "looking"

    assert [(e["action"], e["actor"]) for e in alert["events"]] == [
        ("status", "kim"), ("assigned", "kim"), ("note", "kim")
    ]

    assert alert["events"][0]["detail"] == "new -> investigating"


def test_unchanged_values_add_no_history(store, make_alert):

    store.add_alerts([make_alert()])

    store.update_alert(1, status="resolved")

    again = store.update_alert(1, status="resolved")

    assert len(again["events"]) == 1


def test_invalid_status_is_rejected(store, make_alert):

    store.add_alerts([make_alert()])

    with pytest.raises(ValueError):
        store.update_alert(1, status="bogus")

    with pytest.raises(ValueError):
        store.bulk_status([1], "bogus")


def test_clearing_the_note_and_assignee(store, make_alert):

    store.add_alerts([make_alert()])

    store.update_alert(1, assignee="sam", note="x")

    cleared = store.update_alert(1, assignee="", note="")

    assert cleared["assignee"] is None and cleared["note"] is None


def test_bulk_status_skips_unknown_and_unchanged(store, make_alert):

    store.add_alerts([make_alert() for _ in range(3)])

    store.update_alert(3, status="resolved")

    assert store.bulk_status([1, 2, 3, 99], "resolved") == 2

    assert store.get_alert(1)["events"][0]["detail"] == "new -> resolved"


def test_open_filter_hides_closed_alerts(store, make_alert):

    store.add_alerts([make_alert() for _ in range(4)])

    store.update_alert(1, status="resolved")
    store.update_alert(2, status="false_positive")
    store.update_alert(3, status="investigating")

    open_ids = {a["id"] for a in store.list_alerts(status="open")}

    assert open_ids == {3, 4}

    assert len(store.list_alerts(status="all")) == 4
    assert len(store.list_alerts(status="resolved")) == 1


def test_filters_and_search(store, make_alert):

    store.add_alerts([
        make_alert(attack_type="DDoS", risk="Critical", source="replay"),
        make_alert(attack_type="PortScan", src_ip="192.168.1.7"),
        make_alert(attack_type="PortScan", dst_ip="10.9.9.9"),
    ])

    store.update_alert(2, note="scanner in the lab")

    def ids(**filters):
        return [a["id"] for a in store.list_alerts(status="all", **filters)]

    assert ids(risk="Critical") == [1]
    assert ids(attack_type="PortScan") == [3, 2]
    assert ids(source="replay") == [1]
    assert ids(q="192.168.1") == [2]
    assert ids(q="10.9.9.9") == [3]
    assert ids(q="lab") == [2]
    assert ids(q="#3") == [3]


def test_pagination_by_before_id(store, make_alert):

    store.add_alerts([make_alert() for _ in range(5)])

    page = store.list_alerts(limit=2, status="all")

    assert [a["id"] for a in page] == [5, 4]

    older = store.list_alerts(limit=2, status="all", before_id=page[-1]["id"])

    assert [a["id"] for a in older] == [3, 2]


def test_stats_and_traffic_counters(store, make_alert):

    store.add_alerts([
        make_alert(attack_type="DDoS", risk="High"),
        make_alert(attack_type="DDoS", risk="Critical", source="replay"),
        make_alert(attack_type="Bot", risk="High"),
    ])

    store.add_traffic("capture", 1000, 2)
    store.add_traffic("capture", 500, 0)
    store.add_traffic("replay", 100, 1)

    everything = store.stats()

    assert everything["total"] == 1600
    assert everything["alerts"] == 3
    assert everything["by_type"] == {"DDoS": 2, "Bot": 1}
    assert everything["by_status"] == {"new": 3}

    capture = store.stats("capture")

    assert capture["total"] == 1500 and capture["alerts"] == 2

    assert store.sources() == ["capture", "replay"]


def test_clear_source_only_touches_that_source(store, make_alert):

    store.add_alerts([make_alert(source="replay"), make_alert(source="capture")])
    store.update_alert(1, note="x")
    store.add_traffic("replay", 10, 1)
    store.add_traffic("capture", 10, 1)

    store.clear_source("replay")

    assert [a["source"] for a in store.list_alerts(status="all")] == ["capture"]
    assert store.stats("replay")["total"] == 0
    assert store.stats("capture")["total"] == 10

    # handling history of removed alerts goes with them
    count = store.db.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0]

    assert count == 0


def test_prune_keeps_newest_and_anything_being_handled(store, make_alert):

    store.add_alerts([make_alert(source="replay") for _ in range(6)])

    store.update_alert(1, status="investigating")

    store.prune_source("replay", keep=2)

    kept = sorted(a["id"] for a in store.list_alerts(status="all", limit=50))

    assert kept == [1, 5, 6]


def test_notification_log_newest_first(store):

    store.log_notification("webhook", True, 3)
    store.log_notification("email", False, 5, "smtp refused")

    recent = store.recent_notifications()

    assert [(n["channel"], n["ok"]) for n in recent] == [
        ("email", 0), ("webhook", 1)
    ]
    assert recent[0]["detail"] == "smtp refused"


def test_data_survives_reopening(tmp_path, make_alert):

    path = str(tmp_path / "persist.db")

    first = Store(path)
    first.add_alerts([make_alert()])
    first.update_alert(1, status="resolved")
    first.close()

    second = Store(path)

    assert second.get_alert(1)["status"] == "resolved"

    second.close()
