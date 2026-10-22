import numpy as np
import pandas as pd
from scipy.special import expit

from data_loader import clean_features
from bayesian_engine import (
    build_network,
    attack_posteriors,
    benign_surprise,
    calibrated_logodds
)
from feature_extractor import FEATURES
from forest_engine import attack_probability, confirm
from risk_engine import DEFAULT_BANDS, risk_levels

ANOMALY_TYPE = "Anomaly"

# the packages a saved model's objects come from: it must be loaded with the versions that made it
LIBRARIES = ("numpy", "pandas", "scipy", "scikit-learn", "pgmpy")


def library_versions():
    """{package: installed version} for the packages a model depends on."""

    from importlib.metadata import PackageNotFoundError, version

    found = {}

    for name in LIBRARIES:
        try:
            found[name] = version(name)
        except PackageNotFoundError:
            found[name] = None

    return found


class Detector:
    """Scores CICFlowMeter-style flows with the trained Bayesian network.

    When the model carries a random forest it gives a second opinion on every flow, and
    with use_forest on (the default) classifier alerts the forest calls benign are withheld.
    """

    def __init__(self, bundle=None, use_forest=True):

        self.bundle = bundle if bundle is not None else build_network()

        self.threshold = self.bundle.get("threshold", 0.5)

        self.novelty = self.bundle.get("novelty")

        self.anomaly_threshold = (
            self.novelty["anomaly_threshold"] if self.novelty else None
        )

        self.bands = self.bundle.get("risk_bands", DEFAULT_BANDS)

        self.forest = self.bundle.get("forest")

        # versions of the libraries that differ from the ones the model was trained with
        trained = self.bundle.get("card", {}).get("libraries") or {}

        now = library_versions()

        self.library_mismatch = {
            name: {"trained": trained[name], "installed": now.get(name)}
            for name in trained if trained[name] != now.get(name)
        }

        self.use_forest = bool(use_forest and self.forest)

    def discretize(self, flows):
        """Binned evidence (one int column per feature) for raw flows."""

        return self.bundle["discretizer"].transform(
            clean_features(flows.copy())
        )

    def score(self, flows, details=False):
        """
        flows: DataFrame of raw flow features (extra columns are fine).

        A flow is an ATTACK when the classifier is confident it is not
        benign ("classifier"), or when it is far less likely than normal
        traffic under the BENIGN class ("anomaly", reported as type
        Anomaly: something unfamiliar, not a known attack).

        Returns a frame with probability, prediction, attack_type,
        reason, surprise, risk, forest (the second opinion, NaN without a forest)
        and overruled (a classifier alert the forest withheld); details=True
        adds "posterior" ({class: probability}).
        """

        flows = clean_features(flows.copy())

        missing = [c for c in FEATURES if c not in flows.columns]

        if missing:
            raise ValueError(f"missing flow columns: {missing}")

        classes, post = attack_posteriors(self.bundle, flows)

        logodds = calibrated_logodds(self.bundle, flows)

        probability = expit(logodds)

        # How unlike benign traffic, according to the coarse novelty model
        surprise = (
            benign_surprise(self.novelty, flows)
            if self.novelty else np.zeros(len(flows))
        )

        by_classifier = probability > self.threshold

        # The forest's second opinion; it can overrule the classifier, never the novelty check
        second_opinion = np.full(len(flows), np.nan)

        overruled = np.zeros(len(flows), dtype=bool)

        if self.forest:

            second_opinion = attack_probability(self.forest, flows)

            if self.use_forest:
                by_classifier, overruled = confirm(
                    by_classifier, second_opinion, self.forest["threshold"]
                )

        by_anomaly = ~by_classifier & (
            surprise > self.anomaly_threshold
            if self.anomaly_threshold is not None
            else False
        )

        # Most likely attack class, never BENIGN, when something fired
        attack_post = post.copy()

        attack_post[:, list(classes).index("BENIGN")] = -1

        attack_type = np.array(classes)[attack_post.argmax(axis=1)]

        attack_type = np.where(
            by_classifier,
            attack_type,
            np.where(by_anomaly, ANOMALY_TYPE, "BENIGN")
        )

        flagged = by_classifier | by_anomaly

        risk = risk_levels(logodds, by_classifier, self.bands)

        risk = np.where(by_anomaly, "Medium", risk)

        result = pd.DataFrame({
            "probability": probability,
            "prediction": np.where(flagged, "ATTACK", "BENIGN"),
            "attack_type": attack_type,
            "reason": np.where(
                by_classifier,
                "classifier",
                np.where(by_anomaly, "anomaly", "")
            ),
            "surprise": surprise,
            "risk": risk,
            "forest": second_opinion,
            "overruled": overruled
        }, index=flows.index)

        if details:
            result["posterior"] = [
                dict(zip(classes, row.round(4).tolist()))
                for row in post
            ]

        return result
