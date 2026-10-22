import numpy as np
import pandas as pd

from conftest import ROOT as ROOT_DIR
from train_model import conditional_mutual_information, tan_edges


def test_cmi_is_zero_for_conditionally_independent_variables():

    rng = np.random.default_rng(0)

    c = rng.integers(0, 3, 200000)
    x = (rng.random(200000) < 0.2 + 0.2 * c).astype(int)
    y = (rng.random(200000) < 0.7 - 0.2 * c).astype(int)

    assert conditional_mutual_information(x, y, c) < 1e-3


def test_cmi_of_a_copy_is_the_conditional_entropy():

    rng = np.random.default_rng(1)

    c = rng.integers(0, 2, 200000)
    x = (rng.random(200000) < 0.5).astype(int)

    # H(X | C) for fair coins is ln 2
    assert abs(conditional_mutual_information(x, x, c) - np.log(2)) < 5e-3


def test_cmi_sees_dependence_that_only_exists_given_the_class():

    rng = np.random.default_rng(2)

    c = rng.integers(0, 2, 200000)
    x = rng.integers(0, 2, 200000)
    # y copies x in class 1 and is noise in class 0
    y = np.where(c == 1, x, rng.integers(0, 2, 200000))

    assert conditional_mutual_information(x, y, c) > 0.2


def test_tan_links_dependent_features_and_roots_the_tree_at_the_first():

    rng = np.random.default_rng(3)

    n = 50000

    c = rng.integers(0, 2, n)
    a = rng.integers(0, 3, n)
    b = np.where(rng.random(n) < 0.9, a, rng.integers(0, 3, n))
    d = rng.integers(0, 3, n)

    data = pd.DataFrame({"a": a, "b": b, "d": d, "Class": c})

    edges = tan_edges(data, ["a", "b", "d"], "Class")

    assert {("Class", "a"), ("Class", "b"), ("Class", "d")} <= set(edges)

    tree = [e for e in edges if e[0] != "Class"]

    # a tree over three nodes has two edges, all directed away from "a"
    assert len(tree) == 2
    assert ("a", "b") in tree
    assert {child for _, child in tree} == {"b", "d"}


def test_env_file_fills_in_settings_without_overriding_real_ones(tmp_path):

    import envfile

    path = tmp_path / ".env"
    path.write_text("# c\nIDS_DB = a.db\nexport IDS_DATA_DIR='x y'\nIDS_API_KEY=\"k\"\nbad line\nIDS_ADMIN_TOKEN=from-file\n")

    environ = {"IDS_ADMIN_TOKEN": "from-shell"}

    assert sorted(envfile.load(path, environ)) == ["IDS_API_KEY", "IDS_DATA_DIR", "IDS_DB"]
    assert environ["IDS_DB"] == "a.db" and environ["IDS_DATA_DIR"] == "x y" and environ["IDS_API_KEY"] == "k"
    assert environ["IDS_ADMIN_TOKEN"] == "from-shell"
    assert envfile.load(tmp_path / "missing", {}) == []


# -- continuous integration ----------------------------------------------------------------------------------------

def test_the_ci_workflow_is_valid_and_only_runs_things_that_exist():

    import yaml

    root = ROOT_DIR

    workflow = yaml.safe_load((root / ".github" / "workflows" / "ci.yml").read_text())

    assert {"backend", "frontend", "audit", "docker"} <= set(workflow["jobs"])

    # a push and a pull request both run it, with the least permissions it needs
    assert "push" in workflow[True] and "pull_request" in workflow[True]      # PyYAML reads the key "on" as True
    assert workflow["permissions"] == {"contents": "read"}

    text = (root / ".github" / "workflows" / "ci.yml").read_text()

    # the datasets are not in the repository: the CI run must not need them
    assert 'pytest -q -m "not slow"' in text

    # every file it names is there
    for name in ("requirements.txt", "requirements-prod.txt", "frontend/package-lock.json",
                 "deploy/docker/Dockerfile", "deploy/server/docker-compose.yml", "bayesian_ids.pkl"):
        assert (root / name).exists(), name

    # actions are pinned to a major version, never a moving branch
    import re

    for use in re.findall(r"uses: (\S+)", text):
        assert re.search(r"@v\d+$", use), use


def test_dependabot_watches_every_ecosystem_in_use():

    import yaml

    config = yaml.safe_load((ROOT_DIR / ".github" / "dependabot.yml").read_text())

    watched = {u["package-ecosystem"] for u in config["updates"]}

    assert {"pip", "npm", "github-actions", "docker"} <= watched
