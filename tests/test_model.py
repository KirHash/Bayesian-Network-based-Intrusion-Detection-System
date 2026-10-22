"""Checks that need the trained model (and, for some, the dataset)."""
import warnings

import numpy as np
import pandas as pd
import pytest

from conftest import ROOT, needs_dataset, needs_model
from data_loader import load_dataset
from detector import Detector
from drift import DriftMonitor
from feature_extractor import FEATURES

pytestmark = needs_model


@pytest.fixture(scope="module")
def detector():

    return Detector()


def flows(**overrides):
    """One plausible benign web flow, with overrides."""

    row = {
        "Flow Duration": 50000.0, "Flow Packets/s": 120.0,
        "Flow Bytes/s": 20000.0, "Total Fwd Packets": 6,
        "Total Backward Packets": 6, "Average Packet Size": 150.0,
        "Packet Length Mean": 140.0, "Packet Length Std": 200.0,
        "Flow IAT Mean": 4500.0, "Fwd IAT Mean": 9000.0,
        "Init_Win_bytes_forward": 29200, "Destination Port": 443,
        "Bwd Packets/s": 60.0, "Init_Win_bytes_backward": 229,
        "min_seg_size_forward": 32, "Max Packet Length": 1200.0,
        "Fwd Packet Length Max": 400.0, "Total Length of Fwd Packets": 900.0,
        "Bwd Packet Length Mean": 300.0, "Fwd IAT Min": 40.0
    }

    row.update(overrides)

    return pd.DataFrame([row])


def test_all_model_features_are_in_the_test_flow():

    assert set(FEATURES) == set(flows().columns)


@needs_dataset
def test_numpy_posterior_matches_pgmpy_variable_elimination(detector):

    from bayesian_engine import attack_posteriors

    # pgmpy.inference itself imports a module pgmpy has deprecated; nothing
    # in this project does, so only this import is exempted
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=".*StructureScore.*")

        from pgmpy.inference import VariableElimination

    sample = load_dataset(
        str(ROOT / "dataset" / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    ).sample(15, random_state=0)

    classes, post = attack_posteriors(detector.bundle, sample)

    evidence = detector.bundle["discretizer"].transform(sample)

    inference = VariableElimination(detector.bundle["model"])

    for i, (_, row) in enumerate(evidence.iterrows()):

        expected = inference.query(
            ["AttackType"], evidence=row.to_dict(), show_progress=False
        )

        assert np.abs(expected.values - post[i]).max() < 1e-9


def test_scoring_is_deterministic_and_probabilities_normalised(detector):

    first = detector.score(flows(), details=True)
    second = detector.score(flows(), details=True)

    assert first["probability"].iloc[0] == second["probability"].iloc[0]

    assert sum(first["posterior"].iloc[0].values()) == pytest.approx(1, abs=1e-3)


def test_ordinary_web_flow_is_benign(detector):

    result = detector.score(flows())

    assert result["prediction"].iloc[0] == "BENIGN"
    assert result["risk"].iloc[0] == "Low"


def test_nmap_style_probe_is_a_critical_portscan(detector):
    """What a SYN scan looks like once padding and nmap's options are counted."""

    probe = flows(**{
        "Flow Duration": 47.0, "Flow Packets/s": 42553.0,
        "Flow Bytes/s": 170000.0, "Total Fwd Packets": 1,
        "Total Backward Packets": 1, "Average Packet Size": 4.0,
        "Packet Length Mean": 2.7, "Packet Length Std": 2.8,
        "Flow IAT Mean": 47.0, "Fwd IAT Mean": 0.0,
        "Init_Win_bytes_forward": 1024, "Destination Port": 22,
        "Bwd Packets/s": 21276.0, "Init_Win_bytes_backward": 0,
        "min_seg_size_forward": 24, "Max Packet Length": 6.0,
        "Fwd Packet Length Max": 2.0, "Total Length of Fwd Packets": 2.0,
        "Bwd Packet Length Mean": 6.0, "Fwd IAT Min": 0.0
    })

    result = detector.score(probe)

    assert result["attack_type"].iloc[0] == "PortScan"
    assert result["risk"].iloc[0] == "Critical"
    assert result["reason"].iloc[0] == "classifier"


def test_missing_columns_are_named_in_the_error(detector):

    with pytest.raises(ValueError, match="Destination Port"):
        detector.score(flows().drop(columns="Destination Port"))


def test_extra_columns_and_newer_names_are_accepted(detector):

    renamed = flows().rename(columns={
        "Destination Port": "Dst Port", "Total Fwd Packets": "Tot Fwd Pkts"
    })

    renamed["Source IP"] = "10.0.0.1"
    renamed["Anything else"] = "text"

    assert detector.score(renamed)["prediction"].iloc[0] == "BENIGN"


def test_calibration_never_changes_the_ranking(detector):

    from bayesian_engine import calibrated_logodds, intrusion_logodds

    sample = pd.concat([
        flows(), flows(**{"Flow Duration": 10.0, "Flow Packets/s": 90000.0}),
        flows(**{"Destination Port": 22, "Total Fwd Packets": 1})
    ], ignore_index=True)

    raw = intrusion_logodds(detector.bundle, sample)

    calibrated = calibrated_logodds(detector.bundle, sample)

    assert list(np.argsort(raw)) == list(np.argsort(calibrated))


@needs_dataset
def test_drift_monitor_separates_normal_from_shifted_traffic(detector):

    benign = load_dataset(
        str(ROOT / "dataset" / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    )

    benign = benign[benign["Label"] == "BENIGN"].sample(4000, random_state=0)

    def feed(frame):

        monitor = DriftMonitor(detector, window=4000)

        for start in range(0, len(frame), 500):
            part = frame.iloc[start:start + 500]
            monitor.update(part, detector.score(part))

        return monitor.report()

    normal = feed(benign)

    shifted = benign.copy()
    shifted["Flow Duration"] *= 0.001
    shifted["Flow Packets/s"] *= 1000

    drifted = feed(shifted)

    assert normal["status"] == "stable"
    assert drifted["status"] == "drift"
    assert drifted["max_psi"] > 10 * normal["max_psi"]


# -- the random forest's second opinion ----------------------------------------------------------------

def scan_probe():
    """The nmap-style SYN probe from the PortScan test above."""

    return flows(**{
        "Flow Duration": 47.0, "Flow Packets/s": 42553.0,
        "Flow Bytes/s": 170000.0, "Total Fwd Packets": 1,
        "Total Backward Packets": 1, "Average Packet Size": 4.0,
        "Packet Length Mean": 2.7, "Packet Length Std": 2.8,
        "Flow IAT Mean": 47.0, "Fwd IAT Mean": 0.0,
        "Init_Win_bytes_forward": 1024, "Destination Port": 22,
        "Bwd Packets/s": 21276.0, "Init_Win_bytes_backward": 0,
        "min_seg_size_forward": 24, "Max Packet Length": 6.0,
        "Fwd Packet Length Max": 2.0, "Total Length of Fwd Packets": 2.0,
        "Bwd Packet Length Mean": 6.0, "Fwd IAT Min": 0.0
    })


def test_the_model_carries_a_forest_and_reports_its_opinion(detector):

    assert detector.forest is not None and detector.use_forest

    result = detector.score(flows())

    assert 0.0 <= result["forest"].iloc[0] <= 1.0
    assert "overruled" in result.columns


def test_a_benign_flow_gets_a_low_second_opinion_and_a_probe_a_high_one(detector):

    assert detector.score(flows())["forest"].iloc[0] < 0.5
    assert detector.score(scan_probe())["forest"].iloc[0] > 0.5


def test_the_forest_never_creates_alerts_only_withholds_them(detector):

    sample = pd.concat([flows(), scan_probe(), flows(**{"Destination Port": 80})], ignore_index=True)

    on = Detector(detector.bundle, use_forest=True).score(sample)
    off = Detector(detector.bundle, use_forest=False).score(sample)

    # every flow alerted with the forest was alerted without it
    assert ((on["prediction"] == "ATTACK") <= (off["prediction"] == "ATTACK")).all()

    # and a withheld alert is exactly one the classifier raised and the forest doubted
    assert (off["overruled"] == False).all()


def test_overruled_alerts_can_still_surface_as_anomalies(detector, monkeypatch):

    sample = scan_probe()

    # pretend the forest doubts everything: the classifier alert is withheld ...
    monkeypatch.setitem(detector.forest, "threshold", 1.01)

    result = Detector(detector.bundle, use_forest=True).score(sample)

    assert result["overruled"].iloc[0]
    assert result["reason"].iloc[0] != "classifier"


def test_a_model_without_a_forest_still_scores():

    bundle = dict(Detector().bundle)

    bundle.pop("forest")

    detector = Detector(bundle)

    result = detector.score(flows())

    assert detector.forest is None and not detector.use_forest
    assert result["forest"].isna().all() and not result["overruled"].any()


# -- port categories: old models keep their scheme -------------------------------------------------------------

from feature_extractor import Discretizer, port_category


def test_ftp_and_ssh_have_their_own_port_category_in_the_new_scheme():

    ports = [80, 443, 8080, 53, 21, 22, 23, 1023, 3389, 49151, 49152, 65000]

    assert port_category(ports).tolist() == [0, 1, 2, 3, 4, 5, 6, 6, 7, 7, 8, 8]

    # the original scheme, which models trained earlier still use
    assert port_category(ports, scheme=1).tolist() == [0, 1, 2, 3, 4, 4, 4, 4, 5, 5, 6, 6]


def test_a_discretizer_without_a_scheme_is_an_old_one(detector):

    new = Discretizer().fit(pd.concat([flows()] * 50, ignore_index=True))

    assert new.port_scheme == 2

    # a model saved before the attribute existed behaves as scheme 1
    old = Discretizer().fit(pd.concat([flows()] * 50, ignore_index=True))

    del old.port_scheme

    ssh = flows(**{"Destination Port": 22})

    assert new.transform(ssh)["Destination_Port"].iloc[0] == 5
    assert old.transform(ssh)["Destination_Port"].iloc[0] == 4


# -- the libraries a model was trained with -------------------------------------------------------------------

def test_the_installed_model_matches_the_installed_libraries(detector):

    # a model trained here records its libraries, and loading it here finds no difference
    assert set(detector.bundle["card"]["libraries"]) == {"numpy", "pandas", "scipy", "scikit-learn", "pgmpy"}
    assert detector.library_mismatch == {}


def test_a_model_from_other_library_versions_is_noticed(detector):

    from detector import library_versions

    bundle = dict(detector.bundle)

    bundle["card"] = {**bundle["card"], "libraries": {**library_versions(), "scikit-learn": "0.0.1", "pgmpy": None}}

    mismatch = Detector(bundle).library_mismatch

    assert mismatch["scikit-learn"]["trained"] == "0.0.1"
    assert mismatch["scikit-learn"]["installed"] == library_versions()["scikit-learn"]
    assert "pgmpy" in mismatch and "numpy" not in mismatch


def test_a_model_without_the_record_raises_no_alarm(detector):

    bundle = dict(detector.bundle)

    bundle["card"] = {k: v for k, v in bundle["card"].items() if k != "libraries"}

    assert Detector(bundle).library_mismatch == {}


def test_the_ml_stack_is_pinned_exactly_in_both_requirement_files():

    import re

    from conftest import ROOT

    for name in ("requirements.txt", "requirements-prod.txt"):

        text = (ROOT / name).read_text()

        for package in ("numpy", "pandas", "scipy", "scikit-learn", "pgmpy"):
            assert re.search(rf"^{package}==\d+(\.\d+)+$", text, re.M), (name, package)
