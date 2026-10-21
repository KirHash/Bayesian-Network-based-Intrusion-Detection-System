"""
Sanity checks on the deployment files.

These catch typos and mistakes that would only show up on a target machine
(a missing capability, a file the image needs but does not copy). They do
NOT run systemd, Docker or a Windows service: that was not possible here.
What does run for real: PowerShell parses and dry-runs the Windows installer,
and bash syntax-checks the Linux installer.
"""
import configparser
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import ROOT

DEPLOY = ROOT / "deploy"


def package_names(path):

    names = set()

    for line in Path(path).read_text().splitlines():

        line = line.split("#")[0].strip()

        if line:
            names.add(re.split(r"[<>=!~ ]", line)[0].lower())

    return names


# -- requirements -----------------------------------------------------------------

def test_production_requirements_are_a_subset_without_test_tools():

    prod = package_names(ROOT / "requirements-prod.txt")
    full = package_names(ROOT / "requirements.txt")

    assert prod <= full | {"cryptography"}

    # the model is unpickled with pgmpy, and scoring needs the web stack
    assert {"pgmpy", "fastapi", "uvicorn", "scapy", "cryptography"} <= prod

    assert not prod & {"pytest", "httpx", "tabulate"}


def test_every_module_the_server_imports_has_its_package_listed():
    """api.py's third-party imports must all be installable from requirements-prod."""

    prod = package_names(ROOT / "requirements-prod.txt")

    # import name -> distribution name
    needed = {"numpy": "numpy", "pandas": "pandas", "scipy": "scipy",
              "fastapi": "fastapi", "uvicorn": "uvicorn", "pydantic": "pydantic",
              "scapy": "scapy", "pgmpy": "pgmpy", "cryptography": "cryptography"}

    code = "\n".join(
        (ROOT / f).read_text(encoding="utf-8")
        for f in ("api.py", "detector.py", "bayesian_engine.py", "capture_manager.py",
                  "serve.py", "accounts.py", "drift.py", "notifier.py",
                  "flow_features.py", "data_loader.py", "storage.py")
    )

    for module, dist in needed.items():
        if re.search(rf"^\s*(import|from) {module}\b", code, re.M):
            assert dist in prod, f"{module} is imported but {dist} is not in requirements-prod.txt"


# -- Windows ---------------------------------------------------------------------

POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")

windows_only = pytest.mark.skipif(
    not (sys.platform == "win32" and POWERSHELL), reason="needs Windows PowerShell"
)


def powershell(*args):

    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", *args],
        capture_output=True, text=True, timeout=120
    )


@windows_only
@pytest.mark.parametrize("script", ["install-service.ps1", "run-server.ps1"])
def test_windows_scripts_parse(script):

    path = DEPLOY / "windows" / script

    result = powershell(
        "-Command",
        f"$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]"
        f"::ParseFile('{path}',[ref]$t,[ref]$e);$e.Count"
    )

    assert result.stdout.strip() == "0", result.stdout + result.stderr


@windows_only
def test_windows_installer_dry_run_describes_the_task():

    result = powershell(
        "-File", str(DEPLOY / "windows" / "install-service.ps1"),
        "-DryRun", "-ServeArgs", "--self-signed --host 0.0.0.0"
    )

    assert result.returncode == 0, result.stderr

    out = result.stdout

    assert "BayesianIDS" in out
    assert "run-server.ps1" in out and "--self-signed --host 0.0.0.0" in out
    assert "at boot" in out and "restarted" in out
    assert "nothing was registered" in out


@windows_only
def test_windows_installer_refuses_a_real_install_without_administrator_rights():

    import ctypes

    if ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip("running elevated: this would really install the task")

    result = powershell("-File", str(DEPLOY / "windows" / "install-service.ps1"))

    assert result.returncode != 0
    assert "administrator" in (result.stdout + result.stderr).lower()


def test_windows_env_example_is_parsed_by_the_runner_syntax():
    """KEY=value lines: the same pattern run-server.ps1 matches."""

    lines = (DEPLOY / "windows" / "ids.env.example").read_text().splitlines()

    settings = [
        line for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]

    assert settings and all(
        re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*.*$", line) for line in settings
    )


# -- Linux ----------------------------------------------------------------------

def test_systemd_unit_restarts_always_and_is_not_root():

    unit = configparser.ConfigParser(strict=False, interpolation=None)

    unit.optionxform = str

    unit.read(DEPLOY / "linux" / "bayesian-ids.service")

    assert {"Unit", "Service", "Install"} <= set(unit.sections())

    service = unit["Service"]

    assert service["Restart"] == "always"
    assert service["User"] == "ids"
    assert "serve.py" in service["ExecStart"]
    assert "$IDS_SERVE_ARGS" in service["ExecStart"]
    assert service["EnvironmentFile"] == "/etc/bayesian-ids/env"

    # capture rights, and only those
    assert service["AmbientCapabilities"].split() == ["CAP_NET_RAW", "CAP_NET_ADMIN"]
    assert service["CapabilityBoundingSet"] == service["AmbientCapabilities"]
    assert service["NoNewPrivileges"] == "yes"

    assert "AF_PACKET" in service["RestrictAddressFamilies"]

    assert unit["Install"]["WantedBy"] == "multi-user.target"


def test_systemd_unit_and_env_example_agree_on_paths():

    unit = (DEPLOY / "linux" / "bayesian-ids.service").read_text()

    env = (DEPLOY / "linux" / "env.example").read_text()

    data = re.search(r"IDS_DB=(/.+)/ids\.db", env).group(1)

    assert data in unit  # the writable path the service is allowed to use

    assert "--behind-proxy" in env


def working_bash():
    """A bash that runs. On Windows `bash` may be the WSL launcher with no
    distribution behind it, so each candidate is tried."""

    candidates = [
        shutil.which("bash"),
        r"C:\Program Files\Gitinash.exe",
        r"C:\Program Files (x86)\Gitinash.exe",
    ]

    for candidate in candidates:

        if not candidate or not Path(candidate).exists():
            continue

        try:
            probe = subprocess.run(
                [candidate, "-c", "echo ok"], capture_output=True, text=True,
                timeout=30
            )
        except (OSError, subprocess.SubprocessError):
            continue

        if probe.returncode == 0 and probe.stdout.strip() == "ok":
            return candidate

    return None


@pytest.mark.skipif(working_bash() is None, reason="needs a working bash")
def test_linux_installer_has_valid_shell_syntax():

    result = subprocess.run(
        [working_bash(), "-n", str(DEPLOY / "linux" / "install.sh")],
        capture_output=True, text=True
    )

    assert result.returncode == 0, result.stderr


def test_linux_installer_checks_prerequisites_and_leaves_out_the_dataset():

    script = (DEPLOY / "linux" / "install.sh").read_text()

    assert "set -euo pipefail" in script
    assert "EUID" in script

    for required in ("bayesian_ids.pkl", "frontend/dist/index.html"):
        assert required in script

    assert "--exclude='./dataset'" in script
    assert "requirements-prod.txt" in script


# -- Docker -------------------------------------------------------------------

def test_dockerfile_builds_the_dashboard_and_runs_unprivileged_with_a_healthcheck():

    dockerfile = (DEPLOY / "docker" / "Dockerfile").read_text()

    assert "AS frontend" in dockerfile and "npm run build" in dockerfile
    assert "COPY --from=frontend" in dockerfile

    assert re.search(r"^USER ids$", dockerfile, re.M)
    assert "HEALTHCHECK" in dockerfile and "/api/healthz" in dockerfile
    assert "setcap cap_net_raw" in dockerfile

    # the model ships, the dataset does not
    assert "bayesian_ids.pkl" in dockerfile
    assert "dataset" not in dockerfile.lower().replace("not the dataset", "")

    assert "requirements-prod.txt" in dockerfile

    assert '"--behind-proxy"' in dockerfile


def test_everything_the_dockerfile_copies_exists_or_is_built():

    dockerfile = (DEPLOY / "docker" / "Dockerfile").read_text()

    for line in dockerfile.splitlines():

        match = re.match(r"^COPY (?!--from)(.+) \./?\S*$", line)

        if not match:
            continue

        for source in match.group(1).split():

            if "*" in source:
                assert list(ROOT.glob(source)), source
            else:
                assert (ROOT / source).exists(), f"Dockerfile copies {source}, which is missing"


def test_dockerignore_keeps_the_dataset_and_secrets_out_of_the_image():

    ignored = (ROOT / ".dockerignore").read_text().splitlines()

    for entry in ("dataset/", "ids.db*", "notify.json", "certs/", "frontend/node_modules/"):
        assert entry in ignored


def test_compose_grants_only_the_capture_capabilities_and_persists_data():

    yaml = pytest.importorskip("yaml")

    compose = yaml.safe_load((DEPLOY / "docker" / "docker-compose.yml").read_text())

    service = compose["services"]["ids"]

    assert service["cap_add"] == ["NET_RAW", "NET_ADMIN"]
    assert service["restart"] == "unless-stopped"
    assert "ids-data" in compose["volumes"]
    assert any(v.startswith("ids-data:/data") for v in service["volumes"])

    # no bind mount of a file that may not exist (Docker would create a directory)
    assert not any("notify.json" in v for v in service["volumes"])


# -- reverse proxies ------------------------------------------------------------

def test_proxy_examples_forward_websockets_and_the_original_protocol():

    nginx = (DEPLOY / "proxy" / "nginx.conf").read_text()

    assert "proxy_set_header Upgrade" in nginx
    assert "X-Forwarded-Proto" in nginx
    assert "return 301 https://" in nginx
    assert "TLSv1.2 TLSv1.3" in nginx and "SSLv3" not in nginx

    # dataset uploads are streamed and can be gigabytes: the proxy must allow them
    assert "client_max_body_size 4g" in nginx
    assert "proxy_request_buffering off" in nginx

    # Caddy's runnable configuration lives in proxy/ (see test_the_caddy_setup...)


PROXY = ROOT / "proxy"


def test_the_caddy_setup_is_safe_by_default_and_streams_uploads():

    caddyfile = (PROXY / "Caddyfile").read_text()

    # the dashboard is reached through it, with uploads and the live feed unbuffered
    assert "reverse_proxy {$IDS_UPSTREAM:127.0.0.1:8000}" in caddyfile
    assert "flush_interval -1" in caddyfile
    assert "max_size {$IDS_UPLOAD_LIMIT:4GB}" in caddyfile
    assert "read_timeout 1h" in caddyfile

    # listens on this machine only (both loopback addresses: "localhost" tries ::1 first,
    # and a refused connection there costs two seconds on Windows)
    assert "bind {$IDS_BIND:127.0.0.1 ::1}" in caddyfile

    # no admin API, no change to the system certificate store, no surprise port 80
    assert "admin off" in caddyfile
    assert "skip_install_trust" in caddyfile
    assert "auto_https {$IDS_AUTO_HTTPS:disable_redirects}" in caddyfile

    # a real certificate for a public name is one setting away
    assert "tls {$IDS_TLS:internal}" in caddyfile

    assert "header -Server" in caddyfile


def test_the_caddy_installer_checks_the_download_before_using_it():

    script = (PROXY / "install-caddy.ps1").read_text()

    assert "Get-FileHash -Algorithm SHA512" in script
    assert "checksums.txt" in script
    assert "Checksum mismatch" in script

    # the check comes before anything is unpacked
    assert script.index("Checksum mismatch") < script.index("Expand-Archive")

    assert "https://github.com/caddyserver/caddy/releases/download" in script


def test_the_proxy_launcher_explains_a_missing_install():

    launcher = (PROXY / "Start proxy.bat").read_text()

    assert "bin\\caddy.exe" in launcher
    assert "install-caddy.ps1" in launcher


def test_the_downloaded_proxy_binary_is_not_part_of_the_project_files():

    assert "proxy/bin/" in (ROOT / ".dockerignore").read_text().splitlines()
