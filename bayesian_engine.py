import os
import pickle

import numpy as np
from scipy.special import expit, logsumexp


def model_path():
    """The trained model file: IDS_MODEL, default ./bayesian_ids.pkl."""

    return os.environ.get("IDS_MODEL", "bayesian_ids.pkl")


def build_network(path=None):
    """Returns the trained network together with its discretizer."""

    with open(path or model_path(), "rb") as f:

        return pickle.load(f)


def log_joint(bundle, df):
    """
    log P(AttackType, evidence) for every flow in df.

    All features are observed, so the joint is the prior times each
    node's CPD entry, looked up from the flow's own values (a feature's
    CPD may also be conditioned on one other feature, as in a
    tree-augmented network). That is what variable elimination computes
    here, and in numpy it scores a million flows in seconds.

    Returns (classes, n x classes array of log P(class, evidence)).
    """

    model = bundle["model"]

    evidence = bundle["discretizer"].transform(df)

    prior = model.get_cpds("AttackType")

    classes = prior.state_names["AttackType"]

    log_post = np.tile(
        np.log(prior.values),
        (len(evidence), 1)
    )

    for node in evidence.columns:

        cpd = model.get_cpds(node)

        variables = cpd.variables

        # put the class axis last, then index the others by evidence
        class_axis = variables.index("AttackType")

        values = np.moveaxis(cpd.values, class_axis, -1)

        others = [v for v in variables if v != "AttackType"]

        index = tuple(
            np.searchsorted(
                cpd.state_names[v],
                evidence[v].values
            )
            for v in others
        )

        log_post += np.log(values[index])

    return classes, log_post


def attack_posteriors(bundle, df):
    """P(AttackType | evidence) for every flow in df: (classes, n x classes)."""

    classes, log_post = log_joint(bundle, df)

    log_post = log_post - log_post.max(axis=1, keepdims=True)

    post = np.exp(log_post)

    return classes, post / post.sum(axis=1, keepdims=True)


def benign_surprise(bundle, df):
    """
    -log P(evidence, BENIGN): how unlikely each flow is under normal
    traffic. High values mean the flow does not look like anything the
    network saw as benign, whatever the classifier says.
    """

    classes, log_post = log_joint(bundle, df)

    return -log_post[:, list(classes).index("BENIGN")]


def intrusion_logodds(bundle, df):
    """
    log[P(attack | evidence) / P(BENIGN | evidence)] per flow, computed
    from the log joints so it stays exact when P(BENIGN) underflows.
    """

    classes, log_post = log_joint(bundle, df)

    benign = list(classes).index("BENIGN")

    return (
        logsumexp(np.delete(log_post, benign, axis=1), axis=1)
        - log_post[:, benign]
    )


def calibrated_logodds(bundle, df):
    """Log-odds after the (a, b) recalibration fitted on validation data."""

    calibration = bundle.get("calibration", {"a": 1.0, "b": 0.0})

    return (
        calibration["a"] * intrusion_logodds(bundle, df)
        + calibration["b"]
    )


def intrusion_probability(bundle, df):
    """Calibrated P(not BENIGN | evidence) per flow, as a numpy array."""

    return expit(calibrated_logodds(bundle, df))


def predicted_attack_type(bundle, df):

    classes, post = attack_posteriors(bundle, df)

    return np.array(classes)[post.argmax(axis=1)]
