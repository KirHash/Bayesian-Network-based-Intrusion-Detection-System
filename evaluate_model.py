import numpy as np
from scipy.special import expit
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score
)

from data_loader import load_all, train_val_test_split
from bayesian_engine import intrusion_logodds
from detector import Detector


def expected_calibration_error(y_true, probability, bins=15):
    """Weighted gap between predicted and observed attack frequency."""

    edges = np.linspace(0, 1, bins + 1)

    index = np.clip(np.digitize(probability, edges) - 1, 0, bins - 1)

    error = 0.0

    for b in range(bins):

        mask = index == b

        if mask.any():
            error += mask.mean() * abs(
                probability[mask].mean() - y_true[mask].mean()
            )

    return error


if __name__ == "__main__":

    frames = load_all()

    # Same chronological split the model was trained with
    _, _, test = train_val_test_split(frames)

    detector = Detector()

    result = detector.score(test)

    y_true = (test["Label"] != "BENIGN").astype(int).values
    y_pred = (result["prediction"] == "ATTACK").astype(int).values

    print(
        "Test rows:", len(test),
        "| threshold:", detector.threshold,
        "| anomaly threshold:", round(detector.anomaly_threshold, 1)
    )

    print("Accuracy:", accuracy_score(y_true, y_pred))
    print("Precision:", precision_score(y_true, y_pred))
    print("Recall:", recall_score(y_true, y_pred))
    print("F1:", f1_score(y_true, y_pred))

    print(confusion_matrix(y_true, y_pred))

    classifier = (result["reason"] == "classifier").values

    print(
        "\nClassifier alone: "
        f"recall {recall_score(y_true, classifier):.4f}, "
        f"precision {precision_score(y_true, classifier):.4f}"
    )

    print("\nPer label (alerts raised / by anomaly only / typed correctly):")

    by_anomaly = (result["reason"] == "anomaly").values

    for label in sorted(test["Label"].unique()):

        mask = (test["Label"] == label).values

        print(
            f"{label:28s} {mask.sum():7d} flows  "
            f"{y_pred[mask].mean():6.1%} flagged  "
            f"{by_anomaly[mask].mean():6.1%} anomaly-only  "
            f"{(result['attack_type'].values[mask] == label).mean():6.1%} typed correctly"
        )

    # Calibration: raw network vs recalibrated probability of attack
    raw = expit(np.clip(intrusion_logodds(detector.bundle, test), -60, 60))

    calibrated = result["probability"].values

    print("\nProbability quality on test (lower is better):")

    for name, p in (("raw network", raw), ("calibrated", calibrated)):

        print(
            f"  {name:12s} Brier {brier_score_loss(y_true, p):.5f}  "
            f"ECE {expected_calibration_error(y_true, p):.5f}"
        )
