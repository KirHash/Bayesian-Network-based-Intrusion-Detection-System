import numpy as np

LEVELS = ["Low", "Medium", "High", "Critical"]

DEFAULT_BANDS = {"high": 9.2, "critical": 18.4}


def risk_levels(logodds, flagged, bands):
    """
    Risk band per flow from its calibrated log-odds of being an attack.

    The network's probabilities pile up near 1, so plain percentages put
    every alert in "Critical". Bands are cut on the log-odds instead
    (about 4 and 8 "nines" with the defaults); training places them from
    validation data (see train_model.risk_bands) so Medium is where the
    benign false alarms are. Flows that are not flagged are Low.
    """

    logodds = np.asarray(logodds)

    level = np.where(
        logodds >= bands["critical"],
        "Critical",
        np.where(logodds >= bands["high"], "High", "Medium")
    )

    return np.where(flagged, level, "Low")
