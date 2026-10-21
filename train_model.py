import json
import os
import pickle
import shutil
import sys
import time
from datetime import datetime

import numpy as np
import pandas as pd
from scipy.special import expit
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from scipy.sparse.csgraph import breadth_first_order, minimum_spanning_tree
from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.parameter_estimator import DiscreteBayesianEstimator

from data_loader import load_all, train_val_test_split
from feature_extractor import Discretizer, node_name, FEATURES
from bayesian_engine import (
    benign_surprise,
    intrusion_logodds,
    calibrated_logodds,
    model_path
)
from detector import Detector

STRUCTURE_SAMPLE = 300000

# Share of benign training flows allowed to look "anomalous"
ANOMALY_PERCENTILE = 99.5

# The novelty model uses coarse bins: 4 bins per feature. With finer
# bins every benign oddity gets its own well-populated bin and unfamiliar
# traffic stops looking unlikely.
NOVELTY_QUANTILES = [0.25, 0.5, 0.75]

# Log-odds beyond this are clipped when fitting the calibration
LOGODDS_CLIP = 60.0


def conditional_mutual_information(x, y, c):
    """I(X; Y | C) in nats for integer-coded arrays."""

    kx, ky, kc = x.max() + 1, y.max() + 1, c.max() + 1

    joint = np.bincount(
        (c * kx + x) * ky + y, minlength=kc * kx * ky
    ).reshape(kc, kx, ky) / len(x)

    p_c = joint.sum(axis=(1, 2), keepdims=True)
    p_xc = joint.sum(axis=2, keepdims=True)
    p_yc = joint.sum(axis=1, keepdims=True)

    # sum of p(c,x,y) * log[ p(c,x,y) p(c) / (p(c,x) p(c,y)) ]
    ratio = joint * p_c / (p_xc * p_yc + (joint == 0))

    seen = joint > 0

    return float((joint[seen] * np.log(ratio[seen])).sum())


def tan_edges(data, features, class_column):
    """
    Tree-augmented naive Bayes structure (Friedman et al., 1997): the
    class points at every feature, and the features are joined by the
    maximum spanning tree of their conditional mutual information given
    the class, directed away from the first feature.
    """

    codes = {
        column: pd.factorize(data[column], sort=True)[0]
        for column in [*features, class_column]
    }

    n = len(features)

    weight = np.zeros((n, n))

    for i in range(n):
        for j in range(i + 1, n):
            weight[i, j] = weight[j, i] = conditional_mutual_information(
                codes[features[i]], codes[features[j]], codes[class_column]
            )

    # minimum_spanning_tree ignores zero entries, so flip the weights
    # into strictly positive costs
    cost = np.where(
        np.eye(n, dtype=bool), 0.0, weight.max() + 1.0 - weight
    )

    tree = minimum_spanning_tree(cost)

    order, parent = breadth_first_order(
        tree + tree.T, 0, directed=False, return_predecessors=True
    )

    return [
        *((class_column, f) for f in features),
        *((features[parent[i]], features[i]) for i in order[1:])
    ]


def fit_bundle(train, structure="tan", quantiles=None):

    discretizer = (
        Discretizer(quantiles) if quantiles else Discretizer()
    ).fit(train)

    df_bn = discretizer.transform(train)

    df_bn["AttackType"] = train["Label"].values

    if structure == "tan":

        # Structure from a sample: pairwise statistics do not need all rows
        sample = df_bn.sample(
            min(STRUCTURE_SAMPLE, len(df_bn)),
            random_state=0
        )

        edges = tan_edges(
            sample, [node_name(f) for f in FEATURES], "AttackType"
        )

    else:

        edges = [
            ("AttackType", node_name(feature))
            for feature in FEATURES
        ]

    model = DiscreteBayesianNetwork(edges)

    # BDeu prior keeps rare classes / unseen bins from producing NaN CPDs
    estimator = DiscreteBayesianEstimator(
        prior_type="BDeu",
        equivalent_sample_size=10
    ).fit(model, df_bn)

    model.add_cpds(*estimator.parameters_)

    model.check_model()

    return {
        "model": model,
        "discretizer": discretizer,
        "threshold": 0.5
    }


def fit_calibration(bundle, val):
    """
    Platt-style recalibration of the log-odds: z' = a * z + b, fitted
    on held-out validation flows. Monotonic, so it never changes the
    ranking of flows; it only makes the probabilities honest.
    """

    z = np.clip(intrusion_logodds(bundle, val), -LOGODDS_CLIP, LOGODDS_CLIP)

    y = (val["Label"] != "BENIGN").astype(int).values

    # z / 10 keeps the optimiser well conditioned
    fit = LogisticRegression(C=1e6, max_iter=1000).fit(
        (z / 10).reshape(-1, 1),
        y
    )

    return {
        "a": float(fit.coef_[0, 0] / 10),
        "b": float(fit.intercept_[0])
    }


def best_threshold(bundle, val):
    """Threshold on calibrated P(intrusion) that maximises F1 on val."""

    probability = expit(calibrated_logodds(bundle, val))

    y_true = (val["Label"] != "BENIGN").astype(int).values

    candidates = np.unique(np.concatenate([
        np.linspace(0.05, 0.95, 91),
        [0.97, 0.98, 0.99, 0.995, 0.999, 0.9999, 0.99999]
    ]))

    scores = [
        f1_score(y_true, (probability > t).astype(int))
        for t in candidates
    ]

    return float(candidates[int(np.argmax(scores))]), max(scores)


def risk_bands(bundle, val, threshold):
    """
    Place the High / Critical cut-offs from validation flows that the
    classifier flags: High starts above the log-odds of (nearly) every
    benign false alarm, Critical at the median true alert.
    """

    z = calibrated_logodds(bundle, val)

    flagged = expit(z) > threshold

    benign = (val["Label"] == "BENIGN").values

    false_alarms = z[flagged & benign]

    true_alerts = z[flagged & ~benign]

    high = (
        float(np.percentile(false_alarms, 99))
        if len(false_alarms) else float(np.percentile(true_alerts, 10))
    )

    critical = max(float(np.median(true_alerts)), high + 2)

    return {"high": high, "critical": critical}


def benign_reference(bundle, train):
    """
    Bin frequencies of each feature over benign training flows, keyed by
    the bin's actual value (bins need not start at 0 when a feature has
    few distinct values).
    """

    benign = train[train["Label"] == "BENIGN"]

    evidence = bundle["discretizer"].transform(benign)

    reference = {}

    for node in evidence.columns:

        states = [
            int(s)
            for s in bundle["model"].get_cpds(node).state_names[node]
        ]

        counts = evidence[node].value_counts()

        reference[node] = {
            "states": states,
            "freq": [
                float(counts.get(state, 0)) / len(evidence)
                for state in states
            ]
        }

    return reference


def test_metrics(bundle, test):
    """Held-out results the dashboard shows next to the model."""

    result = Detector(bundle).score(test)

    actual = (test["Label"] != "BENIGN").astype(int).values
    flagged = (result["prediction"] == "ATTACK").astype(int).values

    per_label = {}

    for label in sorted(test["Label"].unique()):

        mask = (test["Label"] == label).values

        per_label[label] = {
            "flows": int(mask.sum()),
            "flagged": round(float(flagged[mask].mean()), 4),
            "typed_correctly": round(
                float((result["attack_type"].values[mask] == label).mean()), 4
            )
        }

    return {
        "rows": len(test),
        "precision": round(float(precision_score(actual, flagged, zero_division=0)), 4),
        "recall": round(float(recall_score(actual, flagged, zero_division=0)), 4),
        "f1": round(float(f1_score(actual, flagged, zero_division=0)), 4),
        "per_label": per_label
    }


def save_model(bundle, path):
    """Write the model so a reader never sees half a file, keeping the
    previous one next to it for rollback."""

    if os.path.exists(path):
        shutil.copyfile(path, path + ".previous")

    temporary = path + ".tmp"

    with open(temporary, "wb") as f:
        pickle.dump(bundle, f)

    os.replace(temporary, path)


if __name__ == "__main__":

    structure = sys.argv[1] if len(sys.argv) > 1 else "tan"

    frames = load_all()

    fit, val, test = train_val_test_split(frames)

    print("fit/val/test rows:", len(fit), len(val), len(test))

    start = time.time()

    bundle = fit_bundle(fit, structure)

    # Everything tuned on validation flows the model has not seen
    bundle["calibration"] = fit_calibration(bundle, val)

    threshold, f1 = best_threshold(bundle, val)

    bands = risk_bands(bundle, val, threshold)

    print(
        f"[{structure}] calibration {bundle['calibration']}  "
        f"validation F1 {f1:.4f} at threshold {threshold}  "
        f"risk bands {bands}  ({time.time() - start:.0f}s)"
    )

    # Refit on fit + validation, keep what was tuned above
    train = pd.concat([fit, val], ignore_index=True)

    final = fit_bundle(train, structure)

    final["calibration"] = bundle["calibration"]
    final["threshold"] = threshold
    final["risk_bands"] = bands

    # Flows far less likely than 99.5% of benign training traffic are
    # reported as anomalies even when the classifier calls them benign
    novelty = fit_bundle(train, structure, NOVELTY_QUANTILES)

    benign_train = train[train["Label"] == "BENIGN"]

    novelty["anomaly_threshold"] = float(np.percentile(
        benign_surprise(novelty, benign_train),
        ANOMALY_PERCENTILE
    ))

    final["novelty"] = novelty

    final["reference"] = benign_reference(final, train)

    final["card"] = {
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "structure": structure,
        "training_rows": len(train),
        "classes": train["Label"].value_counts().to_dict(),
        "threshold": threshold,
        "anomaly_percentile": ANOMALY_PERCENTILE,
        "novelty_bins": len(NOVELTY_QUANTILES) + 1,
        "validation_f1": round(f1, 4)
    }

    print(
        "Feature-to-feature edges:",
        sum(1 for e in final["model"].edges() if e[0] != "AttackType")
    )

    # How it does on flows it never saw (the last 30% of every capture)
    final["card"]["test"] = test_metrics(final, test)

    print(
        "Held-out test: precision {precision}, recall {recall}, "
        "F1 {f1} on {rows} flows".format(**final["card"]["test"])
    )

    save_model(final, model_path())

    # the default model keeps the familiar file name; a model stored elsewhere
    # (IDS_MODEL) gets its card beside it
    card_path = (
        "model_card.json" if model_path() == "bayesian_ids.pkl"
        else model_path() + ".card.json"
    )

    with open(card_path, "w") as f:

        json.dump(final["card"], f, indent=2)

    print("Model trained successfully")
