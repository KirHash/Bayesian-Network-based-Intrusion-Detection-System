"""
Safe handling of files uploaded from the dashboard.

Two folders can be written to, nothing else:

    captures   pcap / pcapng files and flow CSVs for the Capture panel
    dataset    CIC-IDS-2017 style CSVs the model is trained on

Names are reduced to a plain file name, extensions are checked per folder,
pcaps must start with a pcap magic number, dataset CSVs must have the
columns the model needs, and uploads are size-limited and written to a
temporary file first, so a half-uploaded file is never picked up.
"""
import os
import re
from datetime import datetime
from pathlib import Path

import pandas as pd

from data_loader import clean_features, dataset_dir
from feature_extractor import FEATURES

AREAS = ("captures", "dataset", "certs")

SUFFIXES = {
    "captures": {".pcap", ".pcapng", ".cap", ".csv"},
    "dataset": {".csv"},
    "certs": {".pem", ".crt", ".cer", ".key"}
}

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ ()+-]{0,150}$")

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",        # classic, both byte orders
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",        # classic, nanosecond
    b"\x0a\x0d\x0d\x0a"                              # pcapng
}

DEFAULT_MAX_MB = 4096


class FileError(ValueError):
    """The upload was refused; the message says why."""


def max_bytes(environ=os.environ):

    return int(environ.get("IDS_MAX_UPLOAD_MB", DEFAULT_MAX_MB)) * 1024 * 1024


def area_dir(area, captures_dir):

    if area == "captures":
        return Path(captures_dir)

    if area == "dataset":
        return Path(dataset_dir())

    if area == "certs":
        return Path(os.environ.get("IDS_CERT_DIR", "certs"))

    raise FileError(f"unknown folder: {area}")


def check_name(area, name):
    """The name if it is acceptable for this folder, else FileError."""

    if area not in AREAS:
        raise FileError(f"unknown folder: {area}")

    if Path(name).name != name or not NAME.match(name):
        raise FileError(
            "file names may use letters, digits, spaces and . _ - ( ) + "
            "and must start with a letter or digit"
        )

    if Path(name).suffix.lower() not in SUFFIXES[area]:
        raise FileError(
            f"{area} accepts {', '.join(sorted(SUFFIXES[area]))} files"
        )

    return name


def check_pcap(path):

    with open(path, "rb") as f:
        head = f.read(4)

    if head not in PCAP_MAGIC:
        raise FileError("this does not look like a pcap or pcapng file")


def check_dataset_csv(path):
    """Header check: Label and every feature the model uses."""

    try:
        header = pd.read_csv(path, nrows=0, encoding="latin-1")
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as error:
        raise FileError(f"not a readable CSV: {error}")

    columns = set(clean_features(header).columns)

    missing = [c for c in ["Label", *FEATURES] if c not in columns]

    if missing:
        raise FileError(
            "missing columns the model needs: " + ", ".join(missing[:6])
            + (" ..." if len(missing) > 6 else "")
            + ". Use the MachineLearningCSV files of CIC-IDS-2017."
        )


def check_capture_csv(path):
    """Capture CSVs only need to be CSV-shaped; columns are checked when used."""

    try:
        pd.read_csv(path, nrows=0, encoding="latin-1")
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as error:
        raise FileError(f"not a readable CSV: {error}")


def check_certificate(name, path):
    """A PEM file of the right kind: a key must hold a private key, the rest a certificate."""

    head = Path(path).read_bytes()[:200_000].decode("latin-1")

    if "-----BEGIN" not in head:
        raise FileError("this is not a PEM file (it should start with -----BEGIN ...)")

    wants_key = Path(name).suffix.lower() == ".key"

    if wants_key and "PRIVATE KEY" not in head:
        raise FileError("a .key file must contain a private key")

    if not wants_key and "CERTIFICATE" not in head:
        raise FileError("this file does not contain a certificate")


def check_content(area, name, path):

    if area == "certs":
        return check_certificate(name, path)

    if Path(name).suffix.lower() == ".csv":
        (check_dataset_csv if area == "dataset" else check_capture_csv)(path)
    else:
        check_pcap(path)


def label_counts(path):
    """Rows per label in a dataset CSV (reads one column only)."""

    labels = pd.read_csv(path, usecols=lambda c: c.strip() == "Label",
                         encoding="latin-1").iloc[:, 0].dropna()

    labels = (
        labels.astype(str).str.strip().str.replace("\x96", "-", regex=False)
        .str.replace(r"^Web Attack.*$", "Web Attack", regex=True)
    )

    return {k: int(v) for k, v in labels.value_counts().items()}


def listing(area, captures_dir):
    """Files in a folder, newest first."""

    folder = area_dir(area, captures_dir)

    if not folder.is_dir():
        return []

    out = []

    for path in folder.iterdir():

        if (
            path.is_file()
            and not path.name.startswith(".")
            and path.suffix.lower() in SUFFIXES[area]
        ):
            stat = path.stat()

            out.append({
                "name": path.name,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds")
            })

    return sorted(out, key=lambda f: f["modified"], reverse=True)
