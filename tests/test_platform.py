import asyncio
import threading
import time

import pandas as pd
import pytest

import capture_manager
from capture_manager import CaptureManager
from platform_check import CAP_NET_RAW, diagnose, has_capability
from storage import Store


def status(cap_eff):
    return f"Name:\tpython\nCapPrm:\t0000000000000000\nCapEff:\t{cap_eff:016x}\n"


def on_linux(euid=1000, cap_eff=0, tools=("tcpdump",)):

    return diagnose(
        platform="linux",
        geteuid=lambda: euid,
        proc_status=lambda: status(cap_eff),
        which=lambda name: f"/usr/sbin/{name}" if name in tools else None
    )


# -- capabilities --------------------------------------------------------

def test_capability_bit_is_read_from_proc_status():

    assert has_capability(status(1 << CAP_NET_RAW)) is True
    assert has_capability(status(1 << 12)) is False
    assert has_capability(status(0)) is False
    assert has_capability("no such line") is None
    assert has_capability(None) is None


# -- Linux --------------------------------------------------------------------

def test_linux_root_can_capture():

    report = on_linux(euid=0)

    assert report["can_capture"] and report["privileged"]
    assert report["problems"] == []


def test_linux_user_with_net_raw_can_capture():

    assert on_linux(cap_eff=1 << CAP_NET_RAW)["can_capture"]


def test_linux_unprivileged_user_is_told_how_to_fix_it():

    report = on_linux()

    assert not report["can_capture"] and report["privileged"] is False
    assert "setcap" in report["problems"][0]


def test_linux_without_tcpdump_is_only_a_hint():

    report = on_linux(euid=0, tools=())

    assert report["can_capture"]
    assert any("tcpdump" in hint for hint in report["hints"])


# -- Windows ---------------------------------------------------------------

def windows(npcap, admin):

    return diagnose(
        platform="win32",
        exists=lambda path: npcap and path.endswith("wpcap.dll"),
        windows_admin=lambda: admin
    )


def test_windows_without_npcap_cannot_capture():

    report = windows(npcap=False, admin=True)

    assert not report["can_capture"]
    assert "Npcap" in report["problems"][0]


def test_windows_with_npcap_can_capture_even_unprivileged_with_a_hint():

    report = windows(npcap=True, admin=False)

    assert report["can_capture"] and report["library"] == "Npcap"
    assert any("administrator" in hint for hint in report["hints"])

    assert windows(npcap=True, admin=True)["hints"] == []


# -- macOS and others ----------------------------------------------------------

def test_macos_needs_bpf_access_or_root():

    denied = diagnose(
        platform="darwin", geteuid=lambda: 501,
        exists=lambda p: True, access=lambda p, mode: False
    )

    assert denied["privileged"] is False and denied["can_capture"]
    assert any("ChmodBPF" in hint for hint in denied["hints"])

    assert diagnose(platform="darwin", geteuid=lambda: 0)["privileged"] is True


def test_unknown_platforms_are_reported_not_crashed_on():

    report = diagnose(platform="freebsd13")

    assert report["platform"] == "freebsd13" and report["can_capture"]


def test_this_machine_can_be_diagnosed():

    report = diagnose()

    assert {"platform", "library", "privileged", "can_capture", "problems",
            "hints"} <= set(report)


# -- using the report ----------------------------------------------------------

@pytest.fixture
def loop():

    loop = asyncio.new_event_loop()

    threading.Thread(target=loop.run_forever, daemon=True).start()

    yield loop

    loop.call_soon_threadsafe(loop.stop)


@pytest.fixture
def store(tmp_path):

    store = Store(str(tmp_path / "p.db"))

    yield store

    store.close()


async def nothing(frame, labels=None, source="api"):

    return pd.DataFrame(index=frame.index), []


def test_live_capture_is_refused_with_the_reason_when_it_cannot_work(loop, store):

    manager = CaptureManager(
        nothing, loop, store,
        diagnose=lambda: on_linux()
    )

    with pytest.raises(ValueError, match="setcap"):
        manager.start("interface", "eth0")

    assert manager.status()["state"] == "stopped"


def test_files_do_not_need_capture_rights(loop, store, tmp_path):

    from conftest import write_pcap

    write_pcap(tmp_path / "x.pcap", flows=1)

    manager = CaptureManager(
        nothing, loop, store, data_dir=str(tmp_path),
        diagnose=lambda: on_linux()
    )

    manager.start("pcap", "x.pcap")

    deadline = time.time() + 15

    while time.time() < deadline and manager.status()["state"] != "finished":
        time.sleep(0.05)

    assert manager.status()["state"] == "finished"


def test_a_missing_filter_compiler_falls_back_to_unfiltered_capture(
    loop, store, monkeypatch
):
    """No tcpdump / libpcap: the first open fails, the second omits the filter."""

    opened = []

    class FakeSniffer:

        def __init__(self, **kwargs):

            self.kwargs = kwargs
            self.thread = threading.Thread(target=lambda: time.sleep(0.2))
            self.exception = None

            opened.append(kwargs)

            if "filter" in kwargs:
                self.exception = RuntimeError(
                    "Cannot compile the filter: tcpdump is not installed"
                )

        def start(self):
            self.thread.start()

        def stop(self):
            pass

    monkeypatch.setattr(capture_manager, "AsyncSniffer", FakeSniffer)

    manager = CaptureManager(
        nothing, loop, store, diagnose=lambda: on_linux(euid=0)
    )

    monkeypatch.setattr(
        CaptureManager, "validate", lambda self, mode, target: target
    )

    manager.start("interface", "eth0")

    deadline = time.time() + 10

    while time.time() < deadline and len(opened) < 2:
        time.sleep(0.05)

    manager.stop()

    assert "filter" in opened[0]
    assert "filter" not in opened[1] and opened[1]["iface"] == "eth0"


def test_other_start_up_errors_are_not_mistaken_for_a_filter_problem(
    loop, store, monkeypatch
):

    opened = []

    class FakeSniffer:

        def __init__(self, **kwargs):

            opened.append(kwargs)
            self.thread = threading.Thread(target=lambda: None)
            self.exception = PermissionError("Operation not permitted")

        def start(self):
            self.thread.start()

        def stop(self):
            pass

    monkeypatch.setattr(capture_manager, "AsyncSniffer", FakeSniffer)
    monkeypatch.setattr(capture_manager, "BACKOFF", [30])

    monkeypatch.setattr(
        CaptureManager, "validate", lambda self, mode, target: target
    )

    manager = CaptureManager(nothing, loop, store, diagnose=lambda: on_linux(euid=0))

    manager.start("interface", "eth0")

    deadline = time.time() + 10

    while time.time() < deadline and manager.status()["state"] != "retrying":
        time.sleep(0.05)

    shown = manager.status()

    manager.stop()

    # opened once: a permission error is not a reason to retry without the filter
    assert len(opened) == 1
    assert shown["state"] == "retrying"
    assert "not permitted" in shown["error"]
