import math

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from flow_features import FlowTable

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"


def tcp(t, forward, payload=0, flags="A", window=8192, options=None):
    """A TCP packet at time t (seconds), client->server when forward."""

    src, dst = (CLIENT, SERVER) if forward else (SERVER, CLIENT)
    sport, dport = (50000, 80) if forward else (80, 50000)

    packet = IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags=flags, window=window,
        options=options or []
    )

    if payload:
        packet = packet / Raw(b"x" * payload)

    # round-trip so lengths / data offsets are computed like on the wire
    packet = IP(bytes(packet))
    packet.time = t

    return packet


def udp(t, forward, payload):

    src, dst = (CLIENT, SERVER) if forward else (SERVER, CLIENT)

    packet = IP(bytes(
        IP(src=src, dst=dst)
        / UDP(sport=40000 if forward else 53, dport=53 if forward else 40000)
        / Raw(b"d" * payload)
    ))
    packet.time = t

    return packet


def run(packets, **kwargs):

    table = FlowTable(**kwargs)

    done = []

    for packet in packets:
        done += table.add(packet)

    return done + table.flush()


@pytest.fixture
def http_flow():
    """Fwd payloads 0, 0, 100; bwd payloads 0, 500, 700; 30 ms long."""

    flows = run([
        tcp(0.000, True, flags="S", window=8192,
            options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 7)]),
        tcp(0.001, False, flags="SA", window=29200),
        tcp(0.002, True, flags="A"),
        tcp(0.010, True, 100, flags="PA"),
        tcp(0.020, False, 500, flags="PA", window=29200),
        tcp(0.030, False, 700, flags="PA", window=29200),
    ])

    assert len(flows) == 1

    return flows[0]


def test_counts_and_lengths(http_flow):

    assert http_flow["Total Fwd Packets"] == 3
    assert http_flow["Total Backward Packets"] == 3
    assert http_flow["Total Length of Fwd Packets"] == 100
    assert http_flow["Fwd Packet Length Max"] == 100
    assert http_flow["Max Packet Length"] == 700
    assert http_flow["Bwd Packet Length Mean"] == pytest.approx(400)
    assert http_flow["Destination Port"] == 80


def test_times_are_microseconds_and_rates_per_second(http_flow):

    assert http_flow["Flow Duration"] == pytest.approx(30000)
    assert http_flow["Flow Packets/s"] == pytest.approx(6 / 0.030)
    assert http_flow["Bwd Packets/s"] == pytest.approx(3 / 0.030)
    assert http_flow["Flow Bytes/s"] == pytest.approx(1300 / 0.030)
    assert http_flow["Flow IAT Mean"] == pytest.approx(30000 / 5)
    # forward packets at 0, 2 and 10 ms
    assert http_flow["Fwd IAT Mean"] == pytest.approx(5000)
    assert http_flow["Fwd IAT Min"] == pytest.approx(2000)


def test_dataset_packet_length_conventions(http_flow):

    assert http_flow["Average Packet Size"] == pytest.approx(1300 / 6)
    # the dataset divides the payload total by n + 1
    assert http_flow["Packet Length Mean"] == pytest.approx(1300 / 7)


def test_tcp_window_and_header(http_flow):

    assert http_flow["Init_Win_bytes_forward"] == 8192
    assert http_flow["Init_Win_bytes_backward"] == 29200
    # SYN carries options (header 32), plain ACKs are 20 bytes
    assert http_flow["min_seg_size_forward"] == 20


def test_first_fin_ends_the_flow_and_a_new_one_starts():

    table = FlowTable()

    assert table.add(tcp(0.0, True, flags="S")) == []
    assert table.add(tcp(0.1, False, flags="SA")) == []

    done = table.add(tcp(0.2, True, flags="FA"))

    assert len(done) == 1 and done[0]["Total Fwd Packets"] == 2

    # same 5-tuple afterwards is a different flow
    assert table.add(tcp(5.0, True, flags="S")) == []
    assert len(table.flows) == 1


def test_flow_timeout_splits_long_flows():

    flows = run([
        tcp(0, True, 10), tcp(60, False, 10),
        tcp(130, True, 10),  # > 120 s after the flow started
    ])

    assert len(flows) == 2
    assert flows[0]["Total Fwd Packets"] + flows[0]["Total Backward Packets"] == 2


def test_idle_flows_expire_in_live_mode():

    table = FlowTable(idle_timeout=15)

    table.add(tcp(0, True, 10))

    assert table.expire(now=10) == []
    assert len(table.expire(now=20)) == 1
    assert table.flows == {}


def test_single_packet_flow_has_zero_rates():

    flow = run([tcp(0, True, 50)])[0]

    assert flow["Flow Duration"] == 0
    assert flow["Flow Packets/s"] == 0 and flow["Flow Bytes/s"] == 0
    assert flow["Flow IAT Mean"] == 0 and flow["Packet Length Std"] == 0
    # no packet from the server: the dataset records -1
    assert flow["Init_Win_bytes_backward"] == -1


def test_udp_flows_use_minus_one_windows():

    flow = run([udp(0, True, 30), udp(0.01, False, 80)])[0]

    assert flow["Protocol"] == 17
    assert flow["Init_Win_bytes_forward"] == -1
    assert flow["Init_Win_bytes_backward"] == -1
    assert flow["Total Length of Fwd Packets"] == 30
    assert flow["Bwd Packet Length Mean"] == 80


def test_non_ip_or_other_protocols_are_ignored():

    from scapy.layers.inet import ICMP

    packet = IP(src=CLIENT, dst=SERVER) / ICMP()
    packet.time = 0

    assert FlowTable().add(packet) == []


def test_all_model_features_present_and_finite(http_flow):

    from feature_extractor import FEATURES

    for name in FEATURES:
        assert name in http_flow
        assert math.isfinite(http_flow[name])


# -- multicast and broadcast are not scored in live capture ------------------------------------------

from flow_features import is_group_address, local_broadcasts


@pytest.mark.parametrize("address, broadcasts, expected", [
    ("239.255.255.250", (), True),            # SSDP
    ("224.0.0.251", (), True),                # mDNS
    ("255.255.255.255", (), True),
    ("ff02::fb", (), True),
    ("192.168.1.255", ("192.168.1.255",), True),
    ("192.168.1.255", (), False),             # only a broadcast when the interface says so
    ("192.168.1.20", ("192.168.1.255",), False),
    ("8.8.8.8", (), False),
    ("not an address", (), False),
])
def test_group_addresses(address, broadcasts, expected):

    assert is_group_address(address, broadcasts) is expected


def to_group(packet, dst):

    packet = IP(bytes(IP(src=CLIENT, dst=dst) / UDP(sport=40000, dport=1900) / Raw(b"M-SEARCH")))
    packet.time = 1.0

    return packet


def test_flows_to_group_addresses_are_skipped_only_when_asked():

    ssdp = to_group(None, "239.255.255.250")

    kept = FlowTable()
    kept.add(ssdp)

    assert len(kept.flows) == 1 and not kept.ignored

    skipping = FlowTable(ignore_groups=True)
    skipping.add(ssdp)

    assert not skipping.flows and len(skipping.ignored) == 1

    # ordinary traffic is untouched
    skipping.add(udp(1.0, True, 20))

    assert len(skipping.flows) == 1


def test_the_interface_broadcast_is_skipped_too():

    table = FlowTable(ignore_groups=True, broadcasts={"192.168.1.255"})

    table.add(to_group(None, "192.168.1.255"))

    assert not table.flows and len(table.ignored) == 1


def test_this_machines_broadcast_addresses_are_found():

    found = local_broadcasts()

    assert all(a.count(".") == 3 for a in found)
