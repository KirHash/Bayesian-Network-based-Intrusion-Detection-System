"""
Drift check for live traffic.

The model was trained on one network at one time. If incoming traffic
stops looking like that, its verdicts stop being trustworthy long before
anyone notices. Two signals are tracked over a sliding window:

* PSI (population stability index) per feature, comparing the bin
  frequencies of flows the detector called benign with the benign
  training flows. 0.1 is a small shift, 0.25 a large one.
* the anomaly rate, compared with the 0.5% the novelty threshold was
  calibrated to.
"""
from collections import deque

import numpy as np

# Textbook cut-offs are 0.1 / 0.25, but held-out benign traffic from later in
# the same captures already peaks near 0.27 (payload size drifts through the
# day), so the cut-offs sit above that natural variation.
PSI_WARN = 0.30
PSI_DRIFT = 0.60

ANOMALY_WARN = 3.0
ANOMALY_DRIFT = 10.0

# Below this many benign flows the PSI is mostly noise
MIN_FLOWS = 1000

# Flows needed before the anomaly rate alone can call drift
MIN_SCORED = 200

EPSILON = 1e-4


def psi(expected, observed):
    """Population stability index between two bin-frequency vectors."""

    expected = np.maximum(np.asarray(expected, dtype=float), EPSILON)

    observed = np.maximum(np.asarray(observed, dtype=float), EPSILON)

    expected = expected / expected.sum()

    observed = observed / observed.sum()

    return float(np.sum((observed - expected) * np.log(observed / expected)))


class DriftMonitor:

    def __init__(self, detector, window=5000):
        """window: number of recent benign-looking flows to compare."""

        self.detector = detector

        self.window = window

        self.reference = detector.bundle.get("reference")

        self.expected_anomaly_rate = (
            1 - detector.bundle["card"]["anomaly_percentile"] / 100
            if "card" in detector.bundle else 0.005
        )

        self.reset()

    def reset(self):

        # Per batch: (flows, {feature: bin counts}); trimmed to the window
        self.batches = deque()
        self.flows = 0

        self.scored = deque()
        self.scored_flows = 0
        self.scored_anomalies = 0

    def update(self, flows, result):
        """flows: raw frame that was scored; result: Detector.score(flows)."""

        if self.reference is None:
            return

        n = len(result)

        anomalies = int((result["reason"] == "anomaly").sum())

        self.scored.append((n, anomalies))
        self.scored_flows += n
        self.scored_anomalies += anomalies

        while self.scored_flows - self.scored[0][0] >= self.window:
            old_n, old_a = self.scored.popleft()
            self.scored_flows -= old_n
            self.scored_anomalies -= old_a

        benign = flows.loc[(result["prediction"] == "BENIGN").values]

        if benign.empty:
            return

        evidence = self.detector.discretize(benign)

        counts = {
            node: self.bin_counts(node, evidence[node].values)
            for node in self.reference
        }

        self.batches.append((len(benign), counts))
        self.flows += len(benign)

        while self.flows - self.batches[0][0] >= self.window:
            old_n, _ = self.batches.popleft()
            self.flows -= old_n

    def bin_counts(self, node, values):
        """Counts per reference bin, plus a last bucket for unseen bins."""

        states = self.reference[node]["states"]

        counts = [int((values == state).sum()) for state in states]

        return np.array(counts + [len(values) - sum(counts)])

    def report(self):

        if self.reference is None:
            return {"status": "unavailable", "flows": 0}

        anomaly_rate = (
            self.scored_anomalies / self.scored_flows
            if self.scored_flows else 0.0
        )

        base = {
            "flows": self.flows,
            "window": self.window,
            "anomaly_rate": anomaly_rate,
            "expected_anomaly_rate": self.expected_anomaly_rate
        }

        ratio = anomaly_rate / self.expected_anomaly_rate

        flood = self.scored_flows >= MIN_SCORED and ratio >= ANOMALY_DRIFT

        if self.flows < MIN_FLOWS:
            # An anomaly flood is visible long before PSI has enough flows
            return {
                **base,
                "status": "drift" if flood else "warming up",
                "features": {}
            }

        totals = {
            node: sum(counts[node] for _, counts in self.batches)
            for node in self.reference
        }

        # the extra bucket has no training frequency: any mass there is drift
        scores = {
            node: psi(self.reference[node]["freq"] + [0.0], totals[node])
            for node in self.reference
        }

        worst = max(scores, key=scores.get)

        if scores[worst] >= PSI_DRIFT or flood:
            status = "drift"
        elif scores[worst] >= PSI_WARN or ratio >= ANOMALY_WARN:
            status = "warning"
        else:
            status = "stable"

        return {
            **base,
            "status": status,
            "max_psi": scores[worst],
            "worst_feature": worst,
            "features": scores
        }
