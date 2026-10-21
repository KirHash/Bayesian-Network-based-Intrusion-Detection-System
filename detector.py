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
from risk_engine import DEFAULT_BANDS, risk_levels

ANOMALY_TYPE = "Anomaly"


class Detector:
    """Scores CICFlowMeter-style flows with the trained Bayesian network."""

    def __init__(self, bundle=None):

        self.bundle = bundle if bundle is not None else build_network()

        self.threshold = self.bundle.get("threshold", 0.5)

        self.novelty = self.bundle.get("novelty")

        self.anomaly_threshold = (
            self.novelty["anomaly_threshold"] if self.novelty else None
        )

        self.bands = self.bundle.get("risk_bands", DEFAULT_BANDS)

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
        reason, surprise and risk; details=True adds "posterior"
        ({class: probability}).
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
            "risk": risk
        }, index=flows.index)

        if details:
            result["posterior"] = [
                dict(zip(classes, row.round(4).tolist()))
                for row in post
            ]

        return result
