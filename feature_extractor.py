import re

import numpy as np
import pandas as pd

# The ACK / SYN / RST / PSH flag-count columns are deliberately absent:
# in CIC-IDS-2017 they do not hold real TCP flag counts (SYN Flag Count
# is identical to Fwd PSH Flags, and every PortScan flow has PSH=1 with
# SYN=ACK=0), so a model using them learns dataset artefacts that no
# real packet capture can reproduce.
#
# Flow columns used as evidence. Each is cut into quantile bins learned
# from the training data (Destination Port gets fixed categories).
FEATURES = [
    "Flow Duration",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Average Packet Size",
    "Packet Length Mean",
    "Packet Length Std",
    "Flow IAT Mean",
    "Fwd IAT Mean",
    "Init_Win_bytes_forward",
    "Destination Port",
    # added after ranking per-class separability on the fit split
    "Bwd Packets/s",
    "Init_Win_bytes_backward",
    "min_seg_size_forward",
    "Max Packet Length",
    "Fwd Packet Length Max",
    "Total Length of Fwd Packets",
    "Bwd Packet Length Mean",
    "Fwd IAT Min"
]

# Column names used by newer CICFlowMeter releases (3.x / 4.x) and what the
# 2017 dataset called the same thing. Applied to incoming flows so their
# CSVs can be fed in unchanged. Written from the tool's documented header,
# not tested against its output: a missing column is reported by name.
ALIASES = {
    "Dst Port": "Destination Port",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Size Avg": "Average Packet Size",
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Seg Size Min": "min_seg_size_forward",
    "Src IP": "Source IP",
    "Dst IP": "Destination IP"
}

# 16 equal-frequency bins per feature (chosen on validation recall)
QUANTILES = list(np.linspace(0, 1, 17)[1:-1])


def node_name(column):

    return re.sub(r"\W+", "_", column).strip("_")


# Port categories. Scheme 1 (models trained before FTP and SSH brute force were in the data) lumps
# every other well-known port together; scheme 2 gives FTP (21) and SSH (22) their own category,
# which is what tells the two brute-force attacks apart. A saved model keeps its own scheme.
PORT_SCHEME = 2


def port_category(port, scheme=PORT_SCHEME):
    """Scheme 2: 0 HTTP, 1 HTTPS, 2 8080, 3 DNS, 4 FTP, 5 SSH, 6 other well-known, 7 registered,
    8 ephemeral. Scheme 1: 0 HTTP, 1 HTTPS, 2 8080, 3 DNS, 4 other well-known, 5 registered, 6 ephemeral."""

    port = np.asarray(port)

    if scheme == 1:
        return np.select(
            [port == 80, port == 443, port == 8080, port == 53, port < 1024, port < 49152],
            [0, 1, 2, 3, 4, 5],
            default=6
        )

    return np.select(
        [port == 80, port == 443, port == 8080, port == 53, port == 21, port == 22, port < 1024, port < 49152],
        [0, 1, 2, 3, 4, 5, 6, 7],
        default=8
    )


class Discretizer:

    def __init__(self, quantiles=QUANTILES):

        self.quantiles = quantiles

        self.edges = {}

        self.port_scheme = PORT_SCHEME

    def fit(self, df):

        for column in FEATURES:

            if column == "Destination Port":
                continue

            edges = np.unique(
                df[column].quantile(self.quantiles).values
            )

            self.edges[column] = edges

        return self

    def transform(self, df):

        data = {}

        for column in FEATURES:

            if column == "Destination Port":
                # models saved before the scheme existed have no such attribute: they use scheme 1
                values = port_category(df[column], getattr(self, "port_scheme", 1))
            else:
                values = np.searchsorted(
                    self.edges[column],
                    df[column].values,
                    side="right"
                )

            data[node_name(column)] = values.astype(int)

        return pd.DataFrame(data, index=df.index)
