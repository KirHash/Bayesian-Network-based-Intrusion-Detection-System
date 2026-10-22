"""
Turns packets into flows with the columns the model was trained on.

CIC-IDS-2017 was produced by the Java CICFlowMeter; this reimplements
its definitions for the 20 features the model uses, on scapy packets:

* a flow is a bidirectional TCP/UDP 5-tuple; "forward" is the direction
  of the first packet seen
* packet lengths are payload bytes (headers excluded)
* times are in microseconds, rates are per second
* a flow ends at the first FIN, after a maximum duration, or (live mode)
  after it has been silent for a while

Where the dataset's own numbers follow a quirk that was measured rather
than documented, the code says so. Known approximations:

* Packet Length Std uses the sample std of the payload lengths
* min_seg_size_forward is the TCP header length; for UDP the dataset
  holds inconsistent values, so 20 (the most common) is used
* flows with a single packet or zero duration have rates and IATs of 0,
  as the dataset does once its infinities and NaNs are cleaned

For exact fidelity, run the Java CICFlowMeter and point live_monitor.py
at its CSV instead.
"""
import ipaddress
from datetime import datetime

import numpy as np

# Importing the layers registers them with scapy; without l2 a pcap's
# Ethernet frames are read back as undecoded Raw packets
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether  # noqa: F401

FLOW_TIMEOUT = 120.0

IDLE_TIMEOUT = 15.0

UDP_MIN_SEG = 20


class Flow:

    def __init__(self, key, src, dst, sport, dport, protocol):

        self.key = key
        self.src, self.dst = src, dst
        self.sport, self.dport = sport, dport
        self.protocol = protocol

        self.times = []
        self.forward = []
        self.payload = []

        self.windows = {True: None, False: None}
        self.min_header = None

    @property
    def start(self):
        return self.times[0]

    @property
    def last(self):
        return self.times[-1]

    def add(self, time, forward, payload, window, header):

        self.times.append(time)
        self.forward.append(forward)
        self.payload.append(payload)

        # TCP window of the first packet seen in each direction
        if window is not None and self.windows[forward] is None:
            self.windows[forward] = window

        if forward and header is not None:
            self.min_header = (
                header if self.min_header is None
                else min(self.min_header, header)
            )

    def features(self):
        """The dataset-named columns (plus addresses) for this flow."""

        times = np.array(self.times)
        forward = np.array(self.forward)
        payload = np.array(self.payload, dtype=float)

        n = len(times)

        fwd_payload = payload[forward]
        bwd_payload = payload[~forward]

        duration_s = float(times.max() - times.min())

        total = float(payload.sum())

        def rate(value):
            return value / duration_s if duration_s > 0 else 0.0

        fwd_iat = np.diff(times[forward]) * 1e6

        is_tcp = self.protocol == 6

        return {
            "Flow Duration": duration_s * 1e6,
            "Flow Packets/s": rate(n),
            "Flow Bytes/s": rate(total),
            "Total Fwd Packets": int(forward.sum()),
            "Total Backward Packets": int((~forward).sum()),
            "Average Packet Size": total / n,
            # The dataset divides by n + 1 here (Avg = Mean * (n + 1) / n)
            "Packet Length Mean": total / (n + 1),
            "Packet Length Std": (
                float(payload.std(ddof=1)) if n > 1 else 0.0
            ),
            "Flow IAT Mean": (
                duration_s * 1e6 / (n - 1) if n > 1 else 0.0
            ),
            "Fwd IAT Mean": float(fwd_iat.mean()) if len(fwd_iat) else 0.0,
            "Init_Win_bytes_forward": (
                self.windows[True]
                if is_tcp and self.windows[True] is not None else -1
            ),
            "Destination Port": self.dport,
            "Bwd Packets/s": rate(int((~forward).sum())),
            "Init_Win_bytes_backward": (
                self.windows[False]
                if is_tcp and self.windows[False] is not None else -1
            ),
            "min_seg_size_forward": (
                self.min_header if is_tcp and self.min_header is not None
                else UDP_MIN_SEG
            ),
            "Max Packet Length": float(payload.max()),
            "Fwd Packet Length Max": (
                float(fwd_payload.max()) if len(fwd_payload) else 0.0
            ),
            "Total Length of Fwd Packets": float(fwd_payload.sum()),
            "Bwd Packet Length Mean": (
                float(bwd_payload.mean()) if len(bwd_payload) else 0.0
            ),
            "Fwd IAT Min": float(fwd_iat.min()) if len(fwd_iat) else 0.0,
            # Context for the analyst, not used by the model
            "Source IP": self.src,
            "Destination IP": self.dst,
            "Source Port": self.sport,
            "Protocol": self.protocol,
            "Timestamp": datetime.fromtimestamp(self.start).isoformat(
                timespec="seconds"
            )
        }


def is_group_address(address, broadcasts=()):
    """Multicast or broadcast: traffic meant for many hosts (service discovery, mDNS, SSDP, NetBIOS).

    CIC-IDS-2017 has almost none of it, so the model reads it as unfamiliar and raises
    alerts on ordinary network chatter. Such flows are not scored. `broadcasts` holds the
    subnet broadcast addresses of the captured interface (see local_broadcasts).
    """

    if address in broadcasts:
        return True

    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False

    return ip.is_multicast or address == "255.255.255.255"


def local_broadcasts():
    """Subnet broadcast addresses of this machine's IPv4 interfaces, e.g. 192.168.1.255."""

    try:
        import psutil
    except ImportError:
        return set()

    found = set()

    for addresses in psutil.net_if_addrs().values():
        for item in addresses:

            if item.family.name != "AF_INET" or not item.netmask:
                continue

            try:
                network = ipaddress.ip_network(f"{item.address}/{item.netmask}", strict=False)
            except ValueError:
                continue

            if network.prefixlen < 31:
                found.add(str(network.broadcast_address))

    return found


class FlowTable:
    """Assembles packets into flows and hands back the finished ones."""

    def __init__(self, flow_timeout=FLOW_TIMEOUT, idle_timeout=IDLE_TIMEOUT, ignore_groups=False, broadcasts=()):

        self.flow_timeout = flow_timeout
        self.idle_timeout = idle_timeout
        self.flows = {}

        # Skip multicast / broadcast destinations (live capture turns this on)
        self.ignore_groups = ignore_groups
        self.broadcasts = set(broadcasts)
        self.ignored = set()

    @staticmethod
    def parse(packet):
        """(src, dst, sport, dport, protocol, payload, window, header) or None."""

        if IP in packet:
            network = packet[IP]
        elif IPv6 in packet:
            network = packet[IPv6]
        else:
            return None

        if TCP in packet:
            segment = packet[TCP]
            protocol, window, header = 6, int(segment.window), int(segment.dataofs) * 4
        elif UDP in packet:
            segment = packet[UDP]
            protocol, window, header = 17, None, None
        else:
            return None

        return (
            network.src, network.dst,
            int(segment.sport), int(segment.dport),
            protocol, len(bytes(segment.payload)), window, header
        )

    def add(self, packet):
        """Feed one scapy packet; returns the flows that just finished."""

        parsed = self.parse(packet)

        if parsed is None:
            return []

        src, dst, sport, dport, protocol, payload, window, header = parsed

        if self.ignore_groups and is_group_address(dst, self.broadcasts):
            self.ignored.add((src, dst, sport, dport, protocol))

            return []

        time = float(packet.time)

        forward_key = (src, dst, sport, dport, protocol)
        reverse_key = (dst, src, dport, sport, protocol)

        done = []

        flow, forward = None, True

        if forward_key in self.flows:
            flow = self.flows[forward_key]
        elif reverse_key in self.flows:
            flow, forward = self.flows[reverse_key], False

        # Past the flow timeout: close it and start a fresh flow
        if flow is not None and time - flow.start > self.flow_timeout:
            done.append(self.close(flow))
            flow = None
            forward = True

        if flow is None:
            flow = Flow(forward_key, src, dst, sport, dport, protocol)
            self.flows[forward_key] = flow

        flow.add(time, forward, payload, window, header)

        # The first FIN ends a TCP flow, as in CICFlowMeter
        if protocol == 6 and int(packet["TCP"].flags) & 0x01:
            done.append(self.close(flow))

        return done

    def close(self, flow):

        self.flows.pop(flow.key, None)

        return flow.features()

    def expire(self, now):
        """Flows silent for longer than the idle timeout (live mode)."""

        return [
            self.close(flow)
            for flow in list(self.flows.values())
            if now - flow.last > self.idle_timeout
        ]

    def flush(self):
        """Everything still open, e.g. at the end of a pcap."""

        return [self.close(flow) for flow in list(self.flows.values())]
