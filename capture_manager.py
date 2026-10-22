"""
Runs traffic capture inside the API server so it can be started and
stopped from the dashboard.

Three inputs, all feeding the same scoring path (source "capture"):

    interface  live packets from a network interface
    pcap       a saved capture file
    csv        a flow CSV that an exporter keeps appending to

Files can only be chosen from one folder (IDS_DATA_DIR, default
./captures), never by arbitrary path. A capture that dies is retried with
a growing delay; settings are saved so it can start again with the server.
"""
import asyncio
import re
import threading
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
from scapy.sendrecv import AsyncSniffer

from flow_features import FlowTable, local_broadcasts
from live_monitor import follow
from platform_check import diagnose

MODES = ("interface", "pcap", "csv")

FILE_SUFFIXES = {
    "pcap": {".pcap", ".pcapng", ".cap"},
    "csv": {".csv"}
}

# Seconds between flushes of finished flows to the scorer
TICK = 2.0

# Waits before retrying a capture that failed
BACKOFF = [5, 10, 30, 60]

# A run that lasted this long counts as healthy and resets the backoff
HEALTHY_AFTER = 60.0

# Rows handed to the scorer at once when following a CSV
CSV_BATCH = 2000

# Kernel-level filter for live capture. Compiling it needs tcpdump / libpcap,
# which some machines lack; the flow table ignores other traffic anyway.
BPF_FILTER = "ip and (tcp or udp)"

FILTER_PROBLEM = re.compile(r"tcpdump|libpcap|bpf|filter", re.I)


class FatalCaptureError(Exception):
    """A failure that retrying cannot fix (bad CSV columns, ...)."""


def list_interfaces():
    """Network interfaces scapy can see; ones with a real address first."""

    from scapy.config import conf

    found = []

    for interface in conf.ifaces.data.values():

        ip = getattr(interface, "ip", "") or ""

        found.append({
            "name": interface.name,
            "description": getattr(interface, "description", "") or "",
            "ip": ip,
            "usable": bool(ip) and not ip.startswith(("127.", "169.254."))
        })

    return sorted(found, key=lambda i: (not i["usable"], i["name"].lower()))


def list_files(data_dir):
    """Capture and CSV files in the data folder, by kind."""

    folder = Path(data_dir)

    out = {kind: [] for kind in FILE_SUFFIXES}

    if folder.is_dir():

        for path in sorted(folder.iterdir()):

            for kind, suffixes in FILE_SUFFIXES.items():
                if path.is_file() and path.suffix.lower() in suffixes:
                    out[kind].append(path.name)

    return out


class CaptureManager:

    def __init__(self, ingest, loop, store, data_dir="captures",
                 on_status=None, idle_timeout=15.0, diagnose=diagnose):
        """
        ingest: async callable (DataFrame, labels, source) -> (result, records)
        loop:   the event loop ingest runs on (capture runs in threads)
        """

        self.ingest = ingest
        self.loop = loop
        self.store = store
        self.data_dir = Path(data_dir)
        self.on_status = on_status
        self.idle_timeout = idle_timeout
        self.diagnose = diagnose

        self.lock = threading.Lock()
        self.thread = None
        self.stop_event = threading.Event()

        self.state = self.blank("stopped")

    # -- status -----------------------------------------------------------

    @staticmethod
    def blank(state, **extra):

        return {
            "state": state,
            "mode": None,
            "target": None,
            "started_at": None,
            "packets": 0,
            "flows": 0,
            "alerts": 0,
            "error": None,
            "retry_in": None,
            **extra
        }

    def status(self):

        with self.lock:
            status = dict(self.state)

        status["autostart"] = bool(self.store.get_setting("capture_autostart"))

        return status

    def set(self, **changes):

        with self.lock:
            self.state.update(changes)

        if self.on_status:
            self.on_status(self.status())

    def add(self, **counts):

        with self.lock:
            for key, value in counts.items():
                self.state[key] += value

    # -- control ----------------------------------------------------------

    def validate(self, mode, target):
        """Raises ValueError unless (mode, target) is something we may open."""

        if mode not in MODES:
            raise ValueError(f"mode must be one of {list(MODES)}")

        if not target:
            raise ValueError("choose an interface or a file")

        if mode == "interface":

            environment = self.diagnose()

            if not environment["can_capture"]:
                raise ValueError(environment["problems"][0])

            names = {i["name"] for i in list_interfaces()}

            if target not in names:
                raise ValueError(f"unknown interface: {target}")

            return target

        # Only plain file names inside the data folder, nothing else
        if Path(target).name != target or target.startswith("."):
            raise ValueError("files must be chosen from the data folder")

        path = self.data_dir / target

        if path.suffix.lower() not in FILE_SUFFIXES[mode]:
            raise ValueError(f"not a {mode} file: {target}")

        if not path.is_file():
            raise ValueError(f"no such file in the data folder: {target}")

        return str(path)

    def start(self, mode, target):
        """Begin capturing; raises ValueError (bad input) or RuntimeError."""

        resolved = self.validate(mode, target)

        with self.lock:

            if self.thread and self.thread.is_alive():
                raise RuntimeError("a capture is already running; stop it first")

            self.stop_event = threading.Event()

            self.state = self.blank(
                "starting", mode=mode, target=target,
                started_at=datetime.now().isoformat(timespec="seconds")
            )

            self.thread = threading.Thread(
                target=self.supervise,
                args=(mode, resolved, self.stop_event),
                name="capture",
                daemon=True
            )

            self.thread.start()

        self.store.set_setting("capture_config", {"mode": mode, "target": target})

        self.set()

    def stop(self, timeout=15.0):

        with self.lock:
            thread, event = self.thread, self.stop_event

        event.set()

        if thread and thread.is_alive():
            thread.join(timeout)

        with self.lock:
            self.state.update(state="stopped", error=None, retry_in=None)

        if self.on_status:
            self.on_status(self.status())

    def set_autostart(self, enabled):

        self.store.set_setting("capture_autostart", bool(enabled))

    def autostart(self):
        """Start the saved capture if auto-start was switched on."""

        config = self.store.get_setting("capture_config")

        if self.store.get_setting("capture_autostart") and config:

            try:
                self.start(config["mode"], config["target"])
            except (ValueError, RuntimeError) as error:
                self.set(state="error", error=f"auto-start failed: {error}")

    # -- the capture thread ------------------------------------------------

    def supervise(self, mode, target, stop):
        """Run the capture, retrying with backoff until stopped."""

        attempt = 0

        while not stop.is_set():

            began = time.time()

            try:

                outcome = (
                    self.run_csv(target, stop) if mode == "csv"
                    else self.run_sniffer(mode, target, stop)
                )

                if outcome == "finished":
                    self.set(state="finished")
                    return

                break

            except FatalCaptureError as error:
                self.set(state="error", error=str(error), retry_in=None)
                return

            except Exception as error:

                if stop.is_set():
                    break

                if time.time() - began > HEALTHY_AFTER:
                    attempt = 0

                delay = BACKOFF[min(attempt, len(BACKOFF) - 1)]

                attempt += 1

                self.set(
                    state="retrying",
                    error=f"{type(error).__name__}: {error}",
                    retry_in=delay
                )

                if stop.wait(delay):
                    break

        self.set(state="stopped", retry_in=None)

    def deliver(self, flows):
        """Score a batch on the server's event loop and count the result."""

        if not len(flows):
            return

        frame = flows if isinstance(flows, pd.DataFrame) else pd.DataFrame(flows)

        future = asyncio.run_coroutine_threadsafe(
            self.ingest(frame, None, "capture"), self.loop
        )

        try:
            result, records = future.result(timeout=120)
        except ValueError as error:
            raise FatalCaptureError(str(error))

        self.add(flows=len(result), alerts=len(records))

        if self.on_status:
            self.on_status(self.status())

    def run_sniffer(self, mode, target, stop):
        """Live interface or pcap file. Returns "finished" or "stopped"."""

        table = FlowTable(idle_timeout=self.idle_timeout, ignore_groups=True, broadcasts=local_broadcasts())

        lock = threading.Lock()

        pending = []

        last_packet = [0.0]

        def on_packet(packet):

            with lock:
                pending.extend(table.add(packet))

            last_packet[0] = float(packet.time)

            self.add(packets=1)

        def open_sniffer(use_filter):

            if mode == "pcap":
                sniffer = AsyncSniffer(offline=target, prn=on_packet, store=False)
            else:
                sniffer = AsyncSniffer(
                    iface=target,
                    **({"filter": BPF_FILTER} if use_filter else {}),
                    prn=on_packet,
                    store=False
                )

            sniffer.start()

            # The sniffer thread reports start-up failures (no Npcap, no
            # permission, unknown interface) only through .exception
            time.sleep(0.5)

            return sniffer

        sniffer = open_sniffer(use_filter=True)

        # No tcpdump / libpcap to compile the filter: capture unfiltered
        if (
            mode == "interface"
            and sniffer.exception is not None
            and FILTER_PROBLEM.search(str(sniffer.exception))
        ):
            sniffer = open_sniffer(use_filter=False)

        if sniffer.exception is not None:
            raise sniffer.exception

        self.set(state="running", error=None, retry_in=None)

        def flush(expire):

            with lock:

                if expire:
                    pending.extend(table.expire(
                        last_packet[0] if mode == "pcap" else time.time()
                    ))

                batch = list(pending)

                pending.clear()

            self.deliver(batch)

        try:

            while not stop.is_set():

                stop.wait(TICK)

                flush(expire=True)

                if not sniffer.thread.is_alive():
                    break

        finally:

            try:
                sniffer.stop()
            except Exception:
                pass

            with lock:
                pending.extend(table.flush())

            flush(expire=False)

        if sniffer.exception is not None:
            raise sniffer.exception

        if stop.is_set():
            return "stopped"

        if mode == "pcap":
            return "finished"

        raise RuntimeError("the packet sniffer stopped unexpectedly")

    def run_csv(self, target, stop):
        """Follow a flow CSV until stopped."""

        self.set(state="running", error=None, retry_in=None)

        for frame in follow(target, stop.is_set):

            for start in range(0, len(frame), CSV_BATCH):
                self.deliver(frame.iloc[start:start + CSV_BATCH])

        return "stopped"
