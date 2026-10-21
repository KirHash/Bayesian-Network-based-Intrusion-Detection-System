"""
"Start the server when I sign in", switchable from the dashboard.

This is a per-user setting, never a system service: it needs no
administrator rights and runs with the signed-in user's own rights.
(Installing a system service from a web page would let anyone who gets
admin on the dashboard take over the machine, so that stays a deliberate
command-line step: see deploy/.)

    Windows   a scheduled task that runs at logon
    Linux     a systemd user unit
    macOS     a launch agent

Secrets are never written into these files: the admin token and API key
should not be needed (accounts and dashboard-created keys live in the
database).
"""
import os
import plistlib
import shlex
import subprocess
import sys
from pathlib import Path

TASK_NAME = "BayesianIDS-Login"

UNIT_NAME = "bayesian-ids.service"

AGENT_LABEL = "com.bayesian-ids"

# Settings carried over from the running server. IDS_ADMIN_TOKEN,
# IDS_API_KEY and IDS_SECRET_KEY are deliberately not on this list.
CARRIED_ENV = (
    "IDS_DB", "IDS_DATA_DIR", "IDS_DATASET_DIR", "IDS_DEMO_DATA", "IDS_MODEL",
    "IDS_NOTIFY_CONFIG", "IDS_MAX_UPLOAD_MB"
)


def carried_environment(environ=os.environ):

    return {k: environ[k] for k in CARRIED_ENV if environ.get(k)}


def mechanism(platform=sys.platform):

    if platform.startswith("win"):
        return "Windows scheduled task (at logon)"

    if platform == "darwin":
        return "launch agent"

    if platform.startswith("linux"):
        return "systemd user unit"

    return None


# -- Windows -----------------------------------------------------------------

def ps_quote(text):
    """A PowerShell single-quoted string."""

    return "'" + str(text).replace("'", "''") + "'"


def windows_register_script(command, cwd, env, log_path):
    """PowerShell that registers the logon task for the current user."""

    assignments = "".join(
        f"$env:{name} = {ps_quote(value)}; " for name, value in env.items()
    )

    run = " ".join(ps_quote(part) for part in command[1:])

    inner = (
        f"{assignments}Set-Location {ps_quote(cwd)}; "
        f"& {ps_quote(command[0])} {run} *>> {ps_quote(log_path)}"
    )

    return "\n".join([
        "$ErrorActionPreference = 'Stop'",
        f"$inner = {ps_quote(inner)}",
        "$action = New-ScheduledTaskAction -Execute 'powershell.exe' "
        "-Argument ('-NoProfile -WindowStyle Hidden -Command ' + "
        "[char]34 + $inner.Replace([string][char]34, '\\' + [char]34) + [char]34) "
        f"-WorkingDirectory {ps_quote(cwd)}",
        "$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME",
        "$settings = New-ScheduledTaskSettingsSet -RestartCount 3 "
        "-RestartInterval (New-TimeSpan -Minutes 1) "
        "-ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries "
        "-DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew",
        f"Register-ScheduledTask -TaskName {ps_quote(TASK_NAME)} -Action $action "
        "-Trigger $trigger -Settings $settings -Force | Out-Null"
    ])


def powershell(script, run=subprocess.run):

    return run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, timeout=60
    )


# -- Linux and macOS ----------------------------------------------------------------

def systemd_unit(command, cwd, env):

    lines = [
        "[Unit]",
        "Description=Bayesian IDS",
        "",
        "[Service]",
        f"WorkingDirectory={cwd}",
        *(f"Environment={shlex.quote(f'{k}={v}')}" for k, v in env.items()),
        "ExecStart=" + " ".join(shlex.quote(part) for part in command),
        "Restart=on-failure",
        "RestartSec=5",
        "",
        "[Install]",
        "WantedBy=default.target",
        ""
    ]

    return "\n".join(lines)


def launch_agent(command, cwd, env, log_path):

    return plistlib.dumps({
        "Label": AGENT_LABEL,
        "ProgramArguments": list(command),
        "WorkingDirectory": str(cwd),
        "EnvironmentVariables": dict(env),
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "StandardOutPath": str(log_path),
        "StandardErrorPath": str(log_path)
    })


class Autostart:

    def __init__(self, platform=sys.platform, run=subprocess.run,
                 home=Path.home(), environ=os.environ):

        self.platform = platform
        self.run = run
        self.home = Path(home)
        self.environ = environ

    @property
    def supported(self):

        return mechanism(self.platform) is not None

    def unit_path(self):

        return self.home / ".config" / "systemd" / "user" / UNIT_NAME

    def agent_path(self):

        return self.home / "Library" / "LaunchAgents" / f"{AGENT_LABEL}.plist"

    def enabled(self):

        if self.platform.startswith("win"):

            result = powershell(
                f"if (Get-ScheduledTask -TaskName {ps_quote(TASK_NAME)} "
                "-ErrorAction SilentlyContinue) { 'yes' } else { 'no' }",
                self.run
            )

            return result.stdout.strip() == "yes"

        if self.platform == "darwin":
            return self.agent_path().exists()

        if self.platform.startswith("linux"):
            return self.unit_path().exists()

        return False

    def enable(self, command, cwd, log_path):
        """Raises RuntimeError with the reason if it could not be set up."""

        env = carried_environment(self.environ)

        if self.platform.startswith("win"):

            result = powershell(
                windows_register_script(command, str(cwd), env, str(log_path)), self.run
            )

            if result.returncode != 0:
                raise RuntimeError(
                    (result.stderr or result.stdout).strip() or "could not register the task"
                )

        elif self.platform == "darwin":

            path = self.agent_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(launch_agent(command, cwd, env, log_path))

            self.checked(["launchctl", "load", "-w", str(path)])

        elif self.platform.startswith("linux"):

            path = self.unit_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(systemd_unit(command, cwd, env))

            self.checked(["systemctl", "--user", "daemon-reload"])
            self.checked(["systemctl", "--user", "enable", UNIT_NAME])

        else:
            raise RuntimeError(f"not supported on {self.platform}")

    def disable(self):

        if self.platform.startswith("win"):

            powershell(
                f"Unregister-ScheduledTask -TaskName {ps_quote(TASK_NAME)} "
                "-Confirm:$false -ErrorAction SilentlyContinue",
                self.run
            )

        elif self.platform == "darwin":

            if self.agent_path().exists():
                self.run(["launchctl", "unload", "-w", str(self.agent_path())],
                         capture_output=True, text=True)
                self.agent_path().unlink()

        elif self.platform.startswith("linux"):

            if self.unit_path().exists():
                self.run(["systemctl", "--user", "disable", UNIT_NAME],
                         capture_output=True, text=True)
                self.unit_path().unlink()
                self.run(["systemctl", "--user", "daemon-reload"],
                         capture_output=True, text=True)

    def checked(self, command):

        result = self.run(command, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            raise RuntimeError(
                (result.stderr or result.stdout).strip() or f"{command[0]} failed"
            )
