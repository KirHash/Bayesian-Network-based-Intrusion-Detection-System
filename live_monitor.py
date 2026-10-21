"""
Follow a CSV that a flow exporter (e.g. the Java CICFlowMeter) keeps
appending to, and send each batch of new flows to the dashboard API,
which scores them and shows the alerts live (source "capture").

    python live_monitor.py live_flows.csv [--api http://127.0.0.1:8000]

Column names of the 2017 dataset and of newer CICFlowMeter releases are
both understood. Set IDS_API_KEY if the server requires a key.
"""
import argparse
import io
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime

import pandas as pd

from data_loader import clean_features
from feature_extractor import FEATURES

POLL_SECONDS = 1.0

RETRY_SECONDS = 3.0

# Flows per request; a busy exporter can append far more per poll
BATCH_SIZE = 500


def follow(path, should_stop=lambda: False):
    """
    Yield DataFrames of newly appended rows, using the file's header.
    Returns when should_stop() becomes true.
    """

    with open(path, "r", encoding="latin-1") as f:

        header = f.readline()

        # Wait for the exporter to write the header
        while not header.endswith("\n"):

            if should_stop():
                return

            time.sleep(POLL_SECONDS)
            f.seek(0)
            header = f.readline()

        buffer = ""

        while not should_stop():

            chunk = f.read()

            if chunk:

                buffer += chunk

                # Only complete lines: a flow may be half-written
                complete, _, buffer = buffer.rpartition("\n")

                if complete:
                    yield pd.read_csv(
                        io.StringIO(header + complete + "\n"),
                        low_memory=False
                    )

            else:
                time.sleep(POLL_SECONDS)


def post_flows(api, flows):
    """POST flows to /api/score, retrying while the API is unreachable."""

    # Strips names, maps newer CICFlowMeter names, fixes inf / NaN
    flows = clean_features(flows.copy())

    missing = [c for c in FEATURES if c not in flows.columns]

    if missing:
        raise SystemExit(f"CSV is missing flow columns: {missing}")

    # Addresses are shown with the alert when the exporter provides them
    columns = FEATURES + [
        c for c in ("Source IP", "Destination IP") if c in flows.columns
    ]

    body = flows[columns].to_json(orient="records").encode()

    key = os.environ.get("IDS_API_KEY")

    request = urllib.request.Request(
        f"{api}/api/score?source=capture",
        data=body,
        headers={
            "Content-Type": "application/json",
            **({"X-API-Key": key} if key else {})
        }
    )

    while True:

        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)

        except urllib.error.HTTPError as error:
            raise SystemExit(f"API rejected the flows: {error.read().decode()}")

        except OSError:
            print(f"API at {api} unreachable, retrying...", flush=True)
            time.sleep(RETRY_SECONDS)


def main(path, api):

    print(f"Watching {path}, sending flows to {api}", flush=True)

    for flows in follow(path):

        for start in range(0, len(flows), BATCH_SIZE):

            result = post_flows(api, flows.iloc[start:start + BATCH_SIZE])

            print(
                f"[{datetime.now():%H:%M:%S}] sent "
                f"{result['scored']} flows, {len(result['alerts'])} alerts",
                flush=True
            )


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument("flows_csv")

    parser.add_argument("--api", default="http://127.0.0.1:8000")

    args = parser.parse_args()

    main(args.flows_csv, args.api.rstrip("/"))
