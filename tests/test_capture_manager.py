import asyncio
import threading
import time

import pandas as pd
import pytest

import capture_manager
from capture_manager import CaptureManager, list_files, list_interfaces
from conftest import pcap_to_csv, write_pcap
from storage import Store


@pytest.fixture
def loop():
    """An event loop running in a thread, like the server's."""

    loop = asyncio.new_event_loop()

    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()

    yield loop

    loop.call_soon_threadsafe(loop.stop)
    thread.join(5)


@pytest.fixture
def store(tmp_path):

    store = Store(str(tmp_path / "c.db"))

    yield store

    store.close()


class Recorder:
    """A stand-in for the server's scorer that records what it is given."""

    def __init__(self):
        self.frames = []
        self.sources = []
        self.fail_with = None

    async def __call__(self, frame, labels=None, source="api"):

        if self.fail_with:
            raise self.fail_with

        self.frames.append(frame)
        self.sources.append(source)

        return pd.DataFrame(index=frame.index), []

    @property
    def rows(self):
        return sum(len(f) for f in self.frames)


@pytest.fixture
def recorder():
    return Recorder()


@pytest.fixture
def manager(loop, store, recorder, tmp_path):

    folder = tmp_path / "captures"
    folder.mkdir()

    return CaptureManager(recorder, loop, store, data_dir=str(folder))


def wait_for(condition, seconds=15):

    deadline = time.time() + seconds

    while time.time() < deadline:

        if condition():
            return True

        time.sleep(0.05)

    return False


# -- what may be opened ------------------------------------------------------

def test_files_are_listed_by_kind(tmp_path):

    folder = tmp_path / "f"
    folder.mkdir()

    for name in ("a.pcap", "b.PCAPNG", "c.csv", "notes.txt", ".hidden.csv"):
        (folder / name).write_text("x")

    (folder / "sub.pcap").mkdir()

    listing = list_files(folder)

    assert listing["pcap"] == ["a.pcap", "b.PCAPNG"]
    assert listing["csv"] == [".hidden.csv", "c.csv"]
    assert list_files(tmp_path / "missing") == {"pcap": [], "csv": []}


def test_interfaces_are_listed_with_usable_ones_first():

    interfaces = list_interfaces()

    assert interfaces and {"name", "ip", "usable"} <= set(interfaces[0])

    flags = [i["usable"] for i in interfaces]

    assert flags == sorted(flags, reverse=True)


@pytest.mark.parametrize("mode, target, message", [
    ("sniff", "x", "mode must be"),
    ("pcap", "", "choose"),
    ("interface", "no-such-interface", "unknown interface"),
    ("pcap", "../outside.pcap", "data folder"),
    ("pcap", "sub/dir.pcap", "data folder"),
    ("pcap", ".hidden.pcap", "data folder"),
    ("pcap", "notes.txt", "not a pcap"),
    ("csv", "x.pcap", "not a csv"),
    ("pcap", "missing.pcap", "no such file"),
])
def test_invalid_requests_are_refused(manager, monkeypatch, mode, target, message):

    # a machine without the right to capture (a CI runner) would answer with that problem first
    monkeypatch.setattr(manager, "diagnose", lambda: {"can_capture": True, "problems": []})

    with pytest.raises(ValueError, match=message):
        manager.start(mode, target)

    assert manager.status()["state"] == "stopped"


# -- running --------------------------------------------------------------

def test_pcap_is_read_to_the_end_and_flows_are_scored(manager, recorder):

    packets, flows = write_pcap(manager.data_dir / "web.pcap", flows=4)

    manager.start("pcap", "web.pcap")

    assert wait_for(lambda: manager.status()["state"] == "finished")

    status = manager.status()

    assert status["packets"] == packets
    assert status["flows"] == flows == recorder.rows
    assert status["error"] is None
    assert set(recorder.sources) == {"capture"}

    frame = pd.concat(recorder.frames)

    assert {"Destination Port", "Source IP", "Flow Duration"} <= set(frame.columns)
    assert set(frame["Destination Port"]) == {443}


def test_start_saves_the_choice_for_next_time(manager, store):

    write_pcap(manager.data_dir / "web.pcap", flows=1)

    manager.start("pcap", "web.pcap")

    assert store.get_setting("capture_config") == {
        "mode": "pcap", "target": "web.pcap"
    }

    wait_for(lambda: manager.status()["state"] == "finished")


def test_second_start_is_refused_while_running(manager):

    csv = manager.data_dir / "live.csv"

    pd.DataFrame({"Destination Port": [80]}).to_csv(csv, index=False)

    manager.start("csv", "live.csv")

    try:
        with pytest.raises(RuntimeError, match="already running"):
            manager.start("csv", "live.csv")
    finally:
        manager.stop()


def test_csv_is_followed_until_stopped(manager, recorder):

    write_pcap(manager.data_dir / "web.pcap", flows=3)

    path = manager.data_dir / "flows.csv"

    pcap_to_csv(manager.data_dir / "web.pcap", path)

    manager.start("csv", "flows.csv")

    try:
        assert wait_for(lambda: recorder.rows == 3)

        assert manager.status()["state"] == "running"

        # rows an exporter appends later are picked up
        extra = pd.read_csv(path)

        extra.to_csv(path, mode="a", header=False, index=False)

        assert wait_for(lambda: recorder.rows == 6, seconds=10)

        # the manager counts a batch just after the scorer returns
        assert wait_for(lambda: manager.status()["flows"] == 6, seconds=5)

    finally:
        manager.stop()

    assert manager.status()["state"] == "stopped"


def test_stop_returns_promptly_and_allows_a_restart(manager):

    csv = manager.data_dir / "idle.csv"

    pd.DataFrame({"Destination Port": [80]}).to_csv(csv, index=False)

    manager.start("csv", "idle.csv")

    wait_for(lambda: manager.status()["state"] == "running")

    began = time.time()

    manager.stop()

    assert time.time() - began < 5
    assert manager.status()["state"] == "stopped"

    manager.start("csv", "idle.csv")

    assert wait_for(lambda: manager.status()["state"] == "running")

    manager.stop()


def test_input_that_cannot_work_is_an_error_not_a_retry_loop(manager, recorder):

    pd.DataFrame({"Destination Port": [80]}).to_csv(
        manager.data_dir / "bad.csv", index=False
    )

    recorder.fail_with = ValueError("missing flow columns: ['Flow Duration']")

    manager.start("csv", "bad.csv")

    assert wait_for(lambda: manager.status()["state"] == "error")

    status = manager.status()

    assert "missing flow columns" in status["error"]
    assert status["retry_in"] is None


def test_a_failing_capture_is_retried_with_backoff(manager, monkeypatch):

    monkeypatch.setattr(capture_manager, "BACKOFF", [0.1])

    write_pcap(manager.data_dir / "web.pcap", flows=1)

    real = CaptureManager.run_sniffer

    attempts = []

    def flaky(self, mode, target, stop):

        attempts.append(time.time())

        if len(attempts) < 3:
            raise OSError("adapter went away")

        return real(self, mode, target, stop)

    monkeypatch.setattr(CaptureManager, "run_sniffer", flaky)

    seen = set()

    manager.on_status = lambda status: seen.add(status["state"])

    manager.start("pcap", "web.pcap")

    assert wait_for(lambda: manager.status()["state"] == "finished")

    assert len(attempts) == 3
    assert "retrying" in seen
    assert manager.status()["error"] is None


def test_stopping_during_a_retry_wait_does_not_hang(manager, monkeypatch):

    monkeypatch.setattr(capture_manager, "BACKOFF", [60])

    write_pcap(manager.data_dir / "web.pcap", flows=1)

    def broken(self, mode, target, stop):
        raise OSError("no adapter")

    monkeypatch.setattr(CaptureManager, "run_sniffer", broken)

    manager.start("pcap", "web.pcap")

    assert wait_for(lambda: manager.status()["state"] == "retrying")

    status = manager.status()

    assert "no adapter" in status["error"] and status["retry_in"] == 60

    began = time.time()

    manager.stop()

    assert time.time() - began < 5
    assert manager.status()["state"] == "stopped"


# -- auto-start -----------------------------------------------------------

def test_autostart_resumes_the_saved_capture(manager, store, recorder):

    write_pcap(manager.data_dir / "web.pcap", flows=2)

    store.set_setting("capture_config", {"mode": "pcap", "target": "web.pcap"})

    manager.autostart()

    assert manager.status()["state"] == "stopped"

    manager.set_autostart(True)

    assert manager.status()["autostart"] is True

    manager.autostart()

    assert wait_for(lambda: manager.status()["state"] == "finished")
    assert recorder.rows == 2


def test_autostart_with_a_vanished_file_reports_instead_of_crashing(manager, store):

    store.set_setting("capture_config", {"mode": "pcap", "target": "gone.pcap"})

    manager.set_autostart(True)

    manager.autostart()

    status = manager.status()

    assert status["state"] == "error"
    assert "auto-start failed" in status["error"]


def test_a_real_interface_that_does_not_exist_is_reported(manager, monkeypatch):
    """Failures inside the sniffer thread must surface, not vanish."""

    monkeypatch.setattr(capture_manager, "BACKOFF", [30])

    monkeypatch.setattr(
        CaptureManager, "validate", lambda self, mode, target: target
    )

    manager.start("interface", "no-such-interface")

    assert wait_for(lambda: manager.status()["state"] == "retrying")

    assert "not found" in manager.status()["error"].lower()

    manager.stop()
