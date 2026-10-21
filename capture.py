"""
Capture real traffic and score it.

    python capture.py --list-interfaces
    python capture.py --iface "Wi-Fi"            # live (needs Npcap / libpcap)
    python capture.py --pcap traffic.pcap        # offline

Packets become flows (see flow_features.py) and are posted in batches to
the dashboard API, where they are scored and shown as source "capture".
Pass --csv to also keep the flows in a dataset-format CSV.

Live capture usually needs administrator / root rights.
"""
import argparse
import csv
import json
import os
import threading
import time
import urllib.error
import urllib.request

from scapy.sendrecv import AsyncSniffer

from flow_features import FlowTable

BATCH = 500

# Flows buffered while the API is down; the oldest are dropped beyond this
MAX_BUFFER = 50000


def list_interfaces():

    from scapy.config import conf

    for name in sorted(conf.ifaces.data):

        interface = conf.ifaces.data[name]

        print(f"{interface.name!r:40} {getattr(interface, 'ip', '') or ''}")


class Uplink:
    """Posts finished flows to /api/score, buffering while the API is down."""

    def __init__(self, api, key, csv_path):

        self.url = f"{api}/api/score?source=capture"
        self.key = key
        self.buffer = []
        self.lock = threading.Lock()
        self.sent = 0
        self.alerts = 0

        self.csv = None

        if csv_path:
            self.csv = open(csv_path, "w", newline="")
            self.writer = None

    def add(self, flows):

        with self.lock:

            self.buffer += flows

            del self.buffer[:-MAX_BUFFER]

    def write_csv(self, flows):

        if not self.csv or not flows:
            return

        if self.writer is None:
            self.writer = csv.DictWriter(self.csv, fieldnames=list(flows[0]))
            self.writer.writeheader()

        self.writer.writerows(flows)
        self.csv.flush()

    def post(self, flows):

        request = urllib.request.Request(
            self.url,
            data=json.dumps(flows, default=float).encode(),
            headers={
                "Content-Type": "application/json",
                **({"X-API-Key": self.key} if self.key else {})
            }
        )

        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    def flush(self):
        """Send what is buffered; returns False if the API was unreachable."""

        with self.lock:
            flows, self.buffer = self.buffer, []

        self.write_csv(flows)

        for start in range(0, len(flows), BATCH):

            chunk = flows[start:start + BATCH]

            try:
                result = self.post(chunk)

            except urllib.error.HTTPError as error:
                # Rejected for a reason retrying cannot fix
                print(f"API rejected flows: {error.read().decode()[:200]}")
                continue

            except OSError:
                print("API unreachable, will retry", flush=True)

                with self.lock:
                    self.buffer = flows[start:] + self.buffer

                return False

            self.sent += len(chunk)
            self.alerts += len(result["alerts"])

            print(
                f"[{time.strftime('%H:%M:%S')}] sent {len(chunk)} flows, "
                f"{len(result['alerts'])} alerts "
                f"(total {self.sent} flows, {self.alerts} alerts)",
                flush=True
            )

        return True


def main():

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])

    source = parser.add_mutually_exclusive_group()
    source.add_argument("--pcap", help="read packets from a pcap file")
    source.add_argument("--iface", help="sniff this network interface")
    source.add_argument("--list-interfaces", action="store_true")

    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--api-key", default=os.environ.get("IDS_API_KEY"))
    parser.add_argument("--csv", help="also write the flows to this CSV")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="seconds between batches sent to the API")
    parser.add_argument("--idle-timeout", type=float, default=15.0,
                        help="live mode: end a flow after this much silence")

    args = parser.parse_args()

    if args.list_interfaces:
        return list_interfaces()

    if not (args.pcap or args.iface):
        parser.error("give --pcap or --iface")

    table = FlowTable(idle_timeout=args.idle_timeout)

    uplink = Uplink(args.api.rstrip("/"), args.api_key, args.csv)

    table_lock = threading.Lock()

    last_packet = [0.0]

    def on_packet(packet):

        with table_lock:
            done = table.add(packet)

        last_packet[0] = float(packet.time)

        if done:
            uplink.add(done)

    if args.pcap:
        sniffer = AsyncSniffer(offline=args.pcap, prn=on_packet, store=False)
    else:
        sniffer = AsyncSniffer(
            iface=args.iface,
            filter="ip and (tcp or udp)",
            prn=on_packet,
            store=False
        )

    print(
        f"Reading {args.pcap}" if args.pcap
        else f"Capturing on {args.iface} (Ctrl+C to stop)",
        flush=True
    )

    sniffer.start()

    try:

        while sniffer.thread.is_alive():

            time.sleep(args.interval)

            # Offline pcaps are timed by their own clock, live by ours
            now = last_packet[0] if args.pcap else time.time()

            with table_lock:
                uplink.add(table.expire(now))

            uplink.flush()

    except KeyboardInterrupt:
        print("\nStopping...")

    finally:

        try:
            sniffer.stop()
        except Exception:
            pass

        with table_lock:
            uplink.add(table.flush())

        # One last try, with a few retries for a briefly unreachable API
        for _ in range(3):
            if uplink.flush():
                break
            time.sleep(2)

    print(f"Done: {uplink.sent} flows sent, {uplink.alerts} alerts")


if __name__ == "__main__":

    main()
