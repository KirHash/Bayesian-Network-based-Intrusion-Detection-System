import glob
import os

import pandas as pd

from feature_extractor import ALIASES


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


def load_dataset(path):

    # Thursday's file has a non-UTF-8 byte in its web-attack labels
    df = pd.read_csv(
        path,
        low_memory=False,
        encoding="latin-1"
    )

    df.columns = df.columns.str.strip()

    # Only the addresses are kept for display; ids and times are not used
    df = df.drop(columns=["Flow ID", "Timestamp"], errors="ignore")

    # Thursday's file ends in ~288k blank rows; they have no label
    df = df.dropna(subset=["Label"]).reset_index(drop=True)

    df["Label"] = (
        df["Label"]
        .str.strip()
        .str.replace("\x96", "-", regex=False)
        # Brute force / XSS / SQL injection look alike at flow level
        .str.replace(r"^Web Attack.*$", "Web Attack", regex=True)
    )

    df = clean_features(df)

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


def train_test_split_by_time(frames, train_fraction=0.7):

    train, test = split_by_time(frames, (train_fraction,))

    return train, test


def train_val_test_split(frames):
    """56% fit / 14% validation / 30% test (test is the same 30% as above)."""

    return split_by_time(frames, (0.56, 0.7))
