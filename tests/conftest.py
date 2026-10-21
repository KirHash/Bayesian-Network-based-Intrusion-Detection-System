import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(ROOT))

needs_model = pytest.mark.skipif(
    not (ROOT / "bayesian_ids.pkl").exists(),
    reason="run train_model.py first"
)

needs_dataset = pytest.mark.skipif(
    not (ROOT / "dataset").exists(),
    reason="dataset/ is missing"
)


@pytest.fixture
def make_alert():
    """Factory for alert records as the API builds them."""

    def make(**overrides):

        record = {
            "time": "2026-01-01T10:00:00",
            "source": "capture",
            "attack_type": "DDoS",
            "reason": "classifier",
            "risk": "High",
            "probability": 99.5,
            "surprise": 12.0,
            "label": None,
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.9",
            "dst_port": 80,
            "posterior": {"BENIGN": 0.005, "DDoS": 0.995},
            "features": {"Destination Port": 80.0}
        }

        record.update(overrides)

        return record

    return make


def write_pcap(path, flows=3):
    """A pcap of ordinary padded-Ethernet TCP sessions; returns (packets, flows)."""

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.packet import Padding, Raw
    from scapy.utils import wrpcap

    packets = []

    def add(packet, when):

        frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / packet

        short = 60 - len(bytes(frame))

        if short > 0:
            frame = frame / Padding(load=bytes(short))

        frame = Ether(bytes(frame))
        frame.time = when

        packets.append(frame)

    for i in range(flows):

        c, s, sp, t0 = f"10.0.1.{10 + i}", "10.0.0.2", 40000 + i, 1_700_000_000.0 + i

        add(IP(src=c, dst=s) / TCP(sport=sp, dport=443, flags="S", window=64240), t0)
        add(IP(src=s, dst=c) / TCP(sport=443, dport=sp, flags="SA", window=65535), t0 + 0.01)
        add(IP(src=c, dst=s) / TCP(sport=sp, dport=443, flags="PA", window=64240) / Raw(b"q" * 300), t0 + 0.02)
        add(IP(src=s, dst=c) / TCP(sport=443, dport=sp, flags="PA", window=65535) / Raw(b"r" * 900), t0 + 0.03)
        add(IP(src=c, dst=s) / TCP(sport=sp, dport=443, flags="FA", window=64240), t0 + 0.04)

    wrpcap(str(path), packets)

    return len(packets), flows


def pcap_to_csv(pcap_path, csv_path):
    """Flow CSV (dataset column names) for the sessions in a pcap."""

    import pandas as pd
    from scapy.utils import rdpcap

    from flow_features import FlowTable

    table, rows = FlowTable(), []

    for packet in rdpcap(str(pcap_path)):
        rows += table.add(packet)

    rows += table.flush()

    pd.DataFrame(rows).to_csv(csv_path, index=False)

    return len(rows)
