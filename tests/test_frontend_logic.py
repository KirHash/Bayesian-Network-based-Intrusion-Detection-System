"""The dashboard's own tests (vitest), run from here when its packages are installed."""
import shutil
import subprocess
from pathlib import Path

import pytest

FRONTEND = Path(__file__).parent.parent / "frontend"


@pytest.mark.skipif(
    shutil.which("npm") is None or not (FRONTEND / "node_modules" / "vitest").exists(),
    reason="run `npm ci` in frontend/ first",
)
def test_the_dashboards_own_tests_pass():

    done = subprocess.run(
        [shutil.which("npm"), "test"], cwd=FRONTEND, capture_output=True, text=True, timeout=300
    )

    assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-2000:]
    assert "failed" not in done.stdout.lower().replace("0 failed", "")


def test_the_dashboard_has_a_test_script_and_ci_runs_it():

    import json

    scripts = json.loads((FRONTEND / "package.json").read_text())["scripts"]

    assert scripts["test"] == "vitest run"

    workflow = (FRONTEND.parent / ".github" / "workflows" / "ci.yml").read_text()

    assert "npm test" in workflow and "npm run build" in workflow
