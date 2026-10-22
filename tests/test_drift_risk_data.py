import numpy as np
import pandas as pd
import pytest

from data_loader import clean_features
from drift import psi
from risk_engine import risk_levels

BANDS = {"high": 2.0, "critical": 8.0}


# -- drift ------------------------------------------------------------------

def test_psi_is_zero_for_identical_and_grows_with_shift():

    same = [0.25, 0.25, 0.25, 0.25]

    assert psi(same, same) == pytest.approx(0, abs=1e-9)

    small = psi(same, [0.3, 0.2, 0.25, 0.25])
    large = psi(same, [0.7, 0.1, 0.1, 0.1])

    assert 0 < small < 0.1 < large


def test_psi_survives_empty_bins_and_unnormalised_counts():

    value = psi([0.5, 0.5, 0.0], [10, 0, 0])

    assert np.isfinite(value) and value > 1

    # counts and frequencies mean the same thing
    assert psi([1, 1], [5, 5]) == pytest.approx(0, abs=1e-9)


# -- risk bands ----------------------------------------------------------------

def test_risk_levels_follow_bands_and_flag():

    logodds = np.array([1.0, 3.0, 9.0, 12.0])

    flagged = np.array([True, True, True, True])

    assert list(risk_levels(logodds, flagged, BANDS)) == [
        "Medium", "High", "Critical", "Critical"
    ]


def test_unflagged_flows_are_always_low():

    logodds = np.array([50.0, 50.0])

    assert list(risk_levels(logodds, np.array([False, True]), BANDS)) == [
        "Low", "Critical"
    ]


def test_band_edges_are_inclusive():

    levels = risk_levels(np.array([2.0, 8.0]), np.array([True, True]), BANDS)

    assert list(levels) == ["High", "Critical"]


# -- cleaning incoming flows --------------------------------------------------

def test_clean_features_handles_inf_nan_and_strings():

    raw = pd.DataFrame({
        " Flow Duration": [1.0, "Infinity", None],
        "Flow Bytes/s": ["12", float("inf"), float("nan")],
        "Label": ["BENIGN", "DDoS", "BENIGN"],
        "Source IP": ["10.0.0.1", "10.0.0.2", None]
    })

    clean = clean_features(raw)

    assert list(clean["Flow Duration"]) == [1.0, 0.0, 0.0]
    assert list(clean["Flow Bytes/s"]) == [12.0, 0.0, 0.0]
    # text columns are left alone
    assert clean["Source IP"].iloc[0] == "10.0.0.1"
    assert list(clean["Label"]) == ["BENIGN", "DDoS", "BENIGN"]


def test_newer_cicflowmeter_names_are_mapped():

    raw = pd.DataFrame({
        "Dst Port": [443],
        "Tot Fwd Pkts": [3],
        "Flow Byts/s": [100.0],
        "Src IP": ["10.0.0.1"]
    })

    clean = clean_features(raw)

    assert {"Destination Port", "Total Fwd Packets", "Flow Bytes/s",
            "Source IP"} <= set(clean.columns)

    assert clean["Destination Port"].iloc[0] == 443


# -- CSE-CIC-IDS2018 files train the same model ---------------------------------------------------------------

import data_loader as dl
import files as fl
from feature_extractor import ALIASES, FEATURES


def csv_2018(path, rows, repeat_header_at=None):
    """A file with the 2018 column names, extra columns the model ignores, and 2018 labels."""

    columns = {v: k for k, v in ALIASES.items() if v in FEATURES}

    header = [columns.get(f, f) for f in FEATURES] + ["Protocol", "Timestamp", "Fwd Header Len", "Label"]

    lines = [",".join(header)]

    for i, label in enumerate(rows):

        if repeat_header_at is not None and i == repeat_header_at:
            lines.append(",".join(header))

        values = [str(10 + i + n) for n in range(len(FEATURES))] + ["6", "14/02/2018 08:31:01", "20", label]
        lines.append(",".join(values))

    path.write_text("\n".join(lines))


@pytest.mark.parametrize("raw, expected", [
    ("Benign", "BENIGN"), ("BENIGN", "BENIGN"),
    ("FTP-BruteForce", "FTP-Patator"), ("SSH-Bruteforce", "SSH-Patator"),
    ("DoS attacks-Hulk", "DoS Hulk"), ("DoS attacks-Slowloris", "DoS slowloris"),
    ("DoS attacks-GoldenEye", "DoS GoldenEye"), ("DoS attacks-SlowHTTPTest", "DoS Slowhttptest"),
    ("DDOS attack-HOIC", "DDoS"), ("DDOS attack-LOIC-UDP", "DDoS"), ("DDoS attacks-LOIC-HTTP", "DDoS"),
    ("Brute Force -Web", "Web Attack"), ("Brute Force -XSS", "Web Attack"), ("SQL Injection", "Web Attack"),
    ("Web Attack \x96 XSS", "Web Attack"), ("Infilteration", "Infiltration"), ("Bot", "Bot"),
    ("PortScan", "PortScan"), ("DoS Hulk", "DoS Hulk"), ("  Benign ", "BENIGN"),
])
def test_labels_of_both_years_share_one_vocabulary(raw, expected):

    assert dl.normalize_labels(pd.Series([raw])).iloc[0] == expected


def test_thinning_caps_each_label_and_keeps_time_order():

    frame = pd.DataFrame({"Label": ["A"] * 100 + ["B"] * 7, "t": list(range(100)) + list(range(7))})

    thin = dl.thin(frame, limit=10)

    assert thin["Label"].value_counts().to_dict() == {"A": 10, "B": 7}

    # the sampled rows are spread over the whole run, in order
    a = thin[thin["Label"] == "A"]["t"].tolist()

    assert a == sorted(a) and a[0] == 0 and a[-1] >= 85


def test_only_a_tenth_of_a_2018_files_benign_flows_is_used_but_all_its_attacks(tmp_path, monkeypatch):

    path = tmp_path / "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv"

    csv_2018(path, ["Benign"] * 3000 + ["DoS attacks-Slowloris"] * 1500)

    monkeypatch.setenv("IDS_MAX_ROWS_PER_LABEL", "2000")

    labels = dl.load_dataset(str(path))["Label"].value_counts().to_dict()

    # benign: a tenth of the 2000-row cap; the attack is capped like any label
    assert labels == {"DoS slowloris": 1500, "BENIGN": 200}


def test_infiltration_is_left_out_because_flows_cannot_show_it(tmp_path, monkeypatch):

    path = tmp_path / "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv"

    csv_2018(path, ["Benign"] * 50 + ["Infilteration"] * 40)

    monkeypatch.setenv("IDS_MAX_ROWS_PER_LABEL", "2000")

    labels = dl.load_dataset(str(path))["Label"].unique().tolist()

    assert labels == ["BENIGN"]

    # it is still counted (and shown) as what it is in the Data panel
    assert fl.label_counts(str(path)) == {"BENIGN": 50, "Infiltration": 40}


def test_a_2017_file_is_not_thinned_that_way(tmp_path, monkeypatch):

    header = "Destination Port," + ",".join(f for f in FEATURES if f != "Destination Port") + ",Label"

    lines = [header] + [",".join(["80"] + ["1"] * (len(FEATURES) - 1) + ["BENIGN"]) for _ in range(3000)]

    path = tmp_path / "Monday-WorkingHours.pcap_ISCX.csv"
    path.write_text("\n".join(lines))

    monkeypatch.setenv("IDS_MAX_ROWS_PER_LABEL", "2000")

    assert len(dl.load_dataset(str(path))) == 2000


def test_a_2018_file_loads_with_aliased_columns_shared_labels_and_no_stray_header(tmp_path, monkeypatch):

    path = tmp_path / "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"

    csv_2018(path, ["Benign"] * 5 + ["FTP-BruteForce"] * 4, repeat_header_at=3)

    monkeypatch.setenv("IDS_MAX_ROWS_PER_LABEL", "1000")

    df = dl.load_dataset(str(path))

    assert set(FEATURES) <= set(df.columns)
    assert sorted(df["Label"].unique()) == ["BENIGN", "FTP-Patator"]
    assert len(df) == 9 and "Label" not in df["Label"].tolist()

    # columns the model does not use are not even read
    assert "Fwd Header Len" not in df.columns and "Timestamp" not in df.columns


def test_label_counts_and_the_header_check_understand_2018_files(tmp_path):

    path = tmp_path / "x.csv"

    csv_2018(path, ["Benign", "Benign", "Infilteration", "DDOS attack-HOIC"], repeat_header_at=2)

    assert fl.label_counts(str(path)) == {"BENIGN": 2, "Infiltration": 1, "DDoS": 1}

    fl.check_dataset_csv(str(path))


def test_the_row_cap_can_be_raised_from_the_environment(monkeypatch):

    monkeypatch.setenv("IDS_MAX_ROWS_PER_LABEL", "250000")
    assert dl.max_rows_per_label() == 250_000

    monkeypatch.setenv("IDS_MAX_ROWS_PER_LABEL", "junk")
    assert dl.max_rows_per_label() == dl.MAX_ROWS_PER_LABEL
