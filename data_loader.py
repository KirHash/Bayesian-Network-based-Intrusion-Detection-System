import glob
import os

import pandas as pd

from feature_extractor import ALIASES, FEATURES


# Descriptive columns that stay as text; the model never reads them
TEXT_COLUMNS = ["Label", "Source IP", "Destination IP"]


def clean_features(df):
    """Numeric-ise every column but the text ones; inf / NaN become 0."""

    df.columns = df.columns.str.strip()

    df = df.rename(columns=ALIASES)

    numeric = [c for c in df.columns if c not in TEXT_COLUMNS]

    # Some columns arrive as strings (e.g. "Infinity")
    for col in numeric:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df[numeric] = df[numeric].replace([float("inf"), -float("inf")], 0)

    df[numeric] = df[numeric].fillna(0)

    return df


# CSE-CIC-IDS2018 (same CICFlowMeter, same columns apart from the names ALIASES maps) calls things
# differently from CIC-IDS-2017. Brought to one vocabulary so that files of both years train one model.
LABEL_NAMES = {
    "Benign": "BENIGN",
    "FTP-BruteForce": "FTP-Patator",
    "SSH-Bruteforce": "SSH-Patator",
    "DoS attacks-GoldenEye": "DoS GoldenEye",
    "DoS attacks-Slowloris": "DoS slowloris",
    "DoS attacks-SlowHTTPTest": "DoS Slowhttptest",
    "DoS attacks-Hulk": "DoS Hulk",
    "DDoS attacks-LOIC-HTTP": "DDoS",
    "DDOS attack-HOIC": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    "Brute Force -Web": "Web Attack",
    "Brute Force -XSS": "Web Attack",
    "SQL Injection": "Web Attack",
    "Infilteration": "Infiltration"
}

# Rows kept per label per file. A day holds hundreds of thousands of near-identical flows of one
# attack, and mostly benign traffic; this keeps training quick and the classes in proportion.
# Rows are sampled evenly, so each label keeps its time order (the split depends on it).
# Raise it with IDS_MAX_ROWS_PER_LABEL if there is memory to spare.
MAX_ROWS_PER_LABEL = 150_000

# Of a CSE-CIC-IDS2018 file's benign flows only this share of the cap is used. Its benign traffic
# holds far more tiny one-packet flows to port 80 than CIC-IDS-2017's, and in quantity they made
# an nmap-style probe of ports 22 and 80 look benign. The attacks of those files are kept whole;
# what the model needs from them is how the attacks look, not a second picture of benign traffic.
NEWER_BENIGN_SHARE = 0.1

# Labels that are not trained on. CSE-CIC-IDS2018's "Infiltration" is a compromised user's ordinary
# software talking to its controller: its flows are statistically the same as benign ones, so a
# model that tries to catch them either finds almost none (0.5% here) or learns to flag benign
# traffic (false alarms rose from 0.5% to 3.4% when it was given the weight to find a third).
# A flow-level detector cannot see it; leaving it out keeps the alerts trustworthy.
LEFT_OUT_LABELS = {"Infiltration"}


def normalize_labels(labels):
    """Label strings in the shared vocabulary (see LABEL_NAMES)."""

    labels = (
        labels.astype(str).str.strip().str.replace("\x96", "-", regex=False)
        # Brute force / XSS / SQL injection look alike at flow level
        .str.replace(r"^Web Attack.*$", "Web Attack", regex=True)
    )

    return labels.replace(LABEL_NAMES)


def max_rows_per_label():

    try:
        return max(1000, int(os.environ.get("IDS_MAX_ROWS_PER_LABEL", MAX_ROWS_PER_LABEL)))
    except ValueError:
        return MAX_ROWS_PER_LABEL


def thin(df, limit=None, limits=None):
    """At most `limit` rows per label (`limits` overrides it for named labels), picked evenly so
    that time order is kept."""

    limit = limit or max_rows_per_label()

    kept = []

    for label, group in df.groupby("Label"):

        cap = (limits or {}).get(label, limit)

        if len(group) > cap:
            group = group.iloc[
                [int(i) for i in pd.Series(range(cap)).mul(len(group) / cap)]
            ]

        kept.append(group)

    return pd.concat(kept).sort_index().reset_index(drop=True)


_KEEP = set(FEATURES) | set(ALIASES) | set(ALIASES.values()) | {"Label"}


def load_dataset(path):

    # Thursday's file has a non-UTF-8 byte in its web-attack labels. Only the columns the model
    # (and the display of addresses) needs are read: ids, times and the other 60 are not used.
    df = pd.read_csv(
        path,
        low_memory=False,
        encoding="latin-1",
        usecols=lambda column: column.strip() in _KEEP or column.strip() in ("Source IP", "Destination IP"),
    )

    df.columns = df.columns.str.strip()

    # CICFlowMeter v3 (the 2018 files) names columns "Dst Port", "Tot Fwd Pkts" ... ; 2017's are spelt out
    newer = "Dst Port" in df.columns

    # Thursday's 2017 file ends in ~288k blank rows; they have no label
    df = df.dropna(subset=["Label"]).reset_index(drop=True)

    df["Label"] = normalize_labels(df["Label"])

    # some 2018 files repeat their header line in the middle of the data
    df = df[(df["Label"] != "Label") & ~df["Label"].isin(LEFT_OUT_LABELS)].reset_index(drop=True)

    limits = {"BENIGN": int(max_rows_per_label() * NEWER_BENIGN_SHARE)} if newer else None

    df = clean_features(thin(df, limits=limits))

    return df


def dataset_dir():
    """Folder of CIC-IDS-2017 CSVs: IDS_DATASET_DIR (or the older
    IDS_DEMO_DATA), default ./dataset."""

    return (
        os.environ.get("IDS_DATASET_DIR")
        or os.environ.get("IDS_DEMO_DATA")
        or "dataset"
    )


def dataset_glob():

    return os.path.join(dataset_dir(), "*.csv")


def load_all(pattern=None):

    pattern = pattern or dataset_glob()


    return {
        path: load_dataset(path)
        for path in sorted(glob.glob(pattern))
    }


def split_by_time(frames, cuts):
    """
    Split every label of every file chronologically at the given
    cumulative fractions, e.g. (0.56, 0.7) gives three parts: the first
    56%, the next 14% and the last 30% of each label in each capture.
    Splitting per label keeps short attacks (e.g. web attacks) in every
    part.
    """

    parts = [[] for _ in range(len(cuts) + 1)]

    for df in frames.values():

        for _, group in df.groupby("Label"):

            bounds = (
                [0]
                + [int(len(group) * cut) for cut in cuts]
                + [len(group)]
            )

            for part, start, end in zip(parts, bounds, bounds[1:]):
                part.append(group.iloc[start:end])

    return [
        pd.concat(part, ignore_index=True)
        for part in parts
    ]


def train_val_test_split(frames):
    """56% fit / 14% validation / 30% test (test is the same 30% as above)."""

    return split_by_time(frames, (0.56, 0.7))
