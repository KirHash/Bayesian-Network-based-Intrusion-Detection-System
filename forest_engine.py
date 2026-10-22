"""
A random forest as a second opinion on the Bayesian network's alerts.

The network is the primary detector: it trains in seconds, gives per-class probabilities that
can be read, and its likelihood powers the novelty check. A forest on the same 20 features is
more accurate (see the README's comparison), so it is used to *confirm*: when the network's
classifier raises an alert but the forest says the flow is benign, the alert is withheld
(and the flow can still surface as an "Anomaly" if it is unfamiliar). The network's own
probability stays the one shown; the forest's goes beside it as "second opinion".
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from feature_extractor import FEATURES

# Kept small on purpose: the model file travels with the Docker image and every backup
FOREST_TREES = 30
FOREST_LEAVES = 1200

# Training rows used, per class at most; rare classes are used whole
PER_CLASS_ROWS = 120_000

THRESHOLD_CANDIDATES = np.round(np.linspace(0.05, 0.95, 19), 2)


def fit_forest(train, seed=0):
    """Fit on a class-capped sample of the training flows."""

    sample = pd.concat([
        group.sample(min(len(group), PER_CLASS_ROWS), random_state=seed)
        for _, group in train.groupby("Label")
    ])

    model = RandomForestClassifier(
        n_estimators=FOREST_TREES,
        max_leaf_nodes=FOREST_LEAVES,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=seed
    ).fit(sample[FEATURES].values.astype(np.float32), sample["Label"].values)

    return {"model": model, "classes": [str(c) for c in model.classes_]}


def attack_probability(forest, flows):
    """P(not BENIGN) per flow according to the forest."""

    proba = forest["model"].predict_proba(flows[FEATURES].values.astype(np.float32))

    return 1.0 - proba[:, forest["classes"].index("BENIGN")]


def confirm(raw_classifier, forest_probability, threshold):
    """Which classifier alerts the forest confirms, and which it overrules."""

    agreed = forest_probability >= threshold

    return raw_classifier & agreed, raw_classifier & ~agreed


def best_confirmation_threshold(raw_classifier, forest_probability, by_novelty, actual_attack):
    """The forest threshold that maximises F1 of the whole rule on validation flows.

    The rule: an alert is a confirmed classifier alert, or a novelty alert on a flow the
    classifier did not already flag. Returns (threshold, f1).
    """

    best = (0.5, -1.0)

    for threshold in THRESHOLD_CANDIDATES:

        confirmed, _ = confirm(raw_classifier, forest_probability, threshold)

        flagged = confirmed | by_novelty

        true_positive = float((flagged & actual_attack).sum())

        precision = true_positive / max(1.0, float(flagged.sum()))
        recall = true_positive / max(1.0, float(actual_attack.sum()))

        f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)

        if f1 > best[1]:
            best = (float(threshold), f1)

    return best
