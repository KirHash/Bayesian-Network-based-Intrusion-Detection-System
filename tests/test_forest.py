"""The random forest that confirms (or overrules) the Bayesian network's classifier alerts."""
import numpy as np
import pandas as pd
import pytest

import forest_engine as fe
from feature_extractor import FEATURES


def flows(rows=600, seed=0):
    """Benign flows near zero, attack flows far from it, in the 20 model features."""

    rng = np.random.default_rng(seed)

    label = np.where(rng.random(rows) < 0.3, "DDoS", "BENIGN")

    values = rng.normal(0, 1, (rows, len(FEATURES))) + (label == "DDoS")[:, None] * 4

    frame = pd.DataFrame(values, columns=FEATURES)

    frame["Label"] = label

    return frame


@pytest.fixture(scope="module")
def trained():

    return fe.fit_forest(flows(800))


def test_the_forest_separates_what_it_was_shown(trained):

    test = flows(400, seed=1)

    p = fe.attack_probability(trained, test)

    attack = (test["Label"] != "BENIGN").values

    assert ((p >= 0.5) == attack).mean() > 0.95
    assert p.min() >= 0 and p.max() <= 1


def test_it_uses_every_class_it_saw_and_keeps_them_in_order(trained):

    assert trained["classes"] == sorted(trained["classes"]) == ["BENIGN", "DDoS"]


def test_training_does_not_use_more_rows_than_the_cap(monkeypatch):

    monkeypatch.setattr(fe, "PER_CLASS_ROWS", 50)
    monkeypatch.setattr(fe, "FOREST_TREES", 3)

    forest = fe.fit_forest(flows(800))

    # 3 trees fitted, on at most 50 rows per class
    assert len(forest["model"].estimators_) == 3
    assert forest["model"].estimators_[0].tree_.n_node_samples[0] <= 100


def test_confirmation_keeps_agreed_alerts_and_overrules_the_rest():

    raw = np.array([True, True, True, False])
    forest = np.array([0.9, 0.2, 0.5, 0.99])

    confirmed, overruled = fe.confirm(raw, forest, 0.5)

    assert confirmed.tolist() == [True, False, True, False]
    assert overruled.tolist() == [False, True, False, False]

    # a flow the classifier did not flag is never turned into an alert by the forest
    assert not confirmed[3]


def test_the_threshold_search_prefers_dropping_false_alarms_without_losing_attacks():

    # three real attacks the forest is sure of, two false alarms it doubts
    raw = np.array([True] * 5)
    forest = np.array([0.99, 0.95, 0.9, 0.1, 0.2])
    actual = np.array([True, True, True, False, False])
    novelty = np.zeros(5, dtype=bool)

    threshold, f1 = fe.best_confirmation_threshold(raw, forest, novelty, actual)

    assert 0.2 < threshold <= 0.9
    assert f1 == pytest.approx(1.0)


def test_novelty_alerts_count_in_the_search():

    raw = np.array([True, False])
    forest = np.array([0.1, 0.0])
    actual = np.array([False, True])
    novelty = np.array([False, True])

    _, f1 = fe.best_confirmation_threshold(raw, forest, novelty, actual)

    assert f1 == pytest.approx(1.0)
