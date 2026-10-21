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
