"""
Compare the Bayesian IDS with standard classifiers on the same data.

Every model trains on the same fit+validation flows and is scored on the
same held-out test flows. The baselines get the 24 raw features the
network uses ("same features") and, as an upper bound, all 78 columns.

    python compare_baselines.py        # writes reports/baselines.md
"""
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, f1_score, precision_score, recall_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from data_loader import load_all, train_val_test_split
from detector import Detector
from feature_extractor import FEATURES
from train_model import fit_bundle

frames = load_all()

fit, val, test = train_val_test_split(frames)

train = pd.concat([fit, val], ignore_index=True)

ALL_COLUMNS = list(train.select_dtypes("number").columns)

y_test = (test["Label"] != "BENIGN").astype(int).values

labels = sorted(test["Label"].unique())

rows = []


def record(name, seconds_fit, predict, columns_note):
    """predict(test) -> (predicted label array, P(attack) array)."""

    start = time.time()

    predicted, p_attack = predict(test)

    seconds_predict = time.time() - start

    flagged = (predicted != "BENIGN").astype(int)

    row = {
        "model": name,
        "features": columns_note,
        "precision": precision_score(y_test, flagged),
        "recall": recall_score(y_test, flagged),
        "f1": f1_score(y_test, flagged),
        "brier": brier_score_loss(y_test, np.clip(p_attack, 0, 1)),
        "train s": seconds_fit,
        "predict s / 100k": seconds_predict / len(test) * 1e5
    }

    for label in labels:

        if label == "BENIGN":
            continue

        mask = (test["Label"] == label).values

        row[f"recall {label}"] = flagged[mask].mean()

    rows.append(row)

    print(f"done: {name}", flush=True)


# Bayesian network, as shipped (classifier + novelty model)
detector = Detector()


def bayes(df):

    result = detector.score(df)

    return (
        np.where(result["prediction"] == "ATTACK", "ATTACK", "BENIGN"),
        result["probability"].values
    )


def bayes_classifier_only(df):

    result = detector.score(df)

    flagged = result["reason"] == "classifier"

    return (
        np.where(flagged, "ATTACK", "BENIGN"),
        result["probability"].values
    )


# Fitting cost: the classifier network (the novelty model is a second,
# coarser fit of the same size)
start = time.time()

fit_bundle(train, "tan")

bayes_seconds = time.time() - start

record("Bayesian network (classifier + novelty)", 2 * bayes_seconds, bayes, str(len(FEATURES)))

record(
    "Bayesian network (classifier only)", bayes_seconds, bayes_classifier_only, str(len(FEATURES))
)


def sklearn_model(name, model, columns, note):

    start = time.time()

    model.fit(train[columns], train["Label"])

    seconds_fit = time.time() - start

    classes = list(model.classes_)

    benign = classes.index("BENIGN")

    def predict(df):

        probabilities = model.predict_proba(df[columns])

        return (
            model.predict(df[columns]),
            1.0 - probabilities[:, benign]
        )

    record(name, seconds_fit, predict, note)


sklearn_model(
    "Decision tree (depth 12)",
    DecisionTreeClassifier(max_depth=12, random_state=0),
    FEATURES, str(len(FEATURES))
)

sklearn_model(
    "Logistic regression",
    make_pipeline(
        StandardScaler(),
        LogisticRegression(max_iter=300)
    ),
    FEATURES, str(len(FEATURES))
)

sklearn_model(
    "Random forest (150 trees)",
    RandomForestClassifier(150, n_jobs=-1, random_state=0),
    FEATURES, str(len(FEATURES))
)

sklearn_model(
    "Gradient boosting",
    HistGradientBoostingClassifier(random_state=0),
    FEATURES, str(len(FEATURES))
)

sklearn_model(
    "Random forest (all columns)",
    RandomForestClassifier(150, n_jobs=-1, random_state=0),
    ALL_COLUMNS, str(len(ALL_COLUMNS))
)

table = pd.DataFrame(rows).set_index("model")

pd.set_option("display.width", 250)
pd.set_option("display.max_columns", 30)

print(table.round(4).to_string())

Path("reports").mkdir(exist_ok=True)

with open("reports/baselines.md", "w") as f:

    f.write(
        f"# Baseline comparison\n\n"
        f"Trained on {len(train):,} flows, tested on {len(test):,} "
        f"held-out flows (last 30% of every label in every capture).\n\n"
    )

    f.write(table.round(4).to_markdown())

    f.write("\n")
