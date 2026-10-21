"""
Stopping and restarting the running server from the dashboard.

serve.py registers the uvicorn server here so it can be asked to exit
cleanly (database closed, captures stopped). When the server was started
some other way, the fallback is to signal the process.
"""
import os
import signal
import subprocess
import sys
from pathlib import Path

SERVER = None

HERE = Path(__file__).resolve().parent


def request_shutdown():
    """Ask the server to exit; it finishes in-flight work first."""

    if SERVER is not None:
        SERVER.should_exit = True
    else:
        signal.raise_signal(signal.SIGINT)


def original_command():
    """The command line this process was started with."""

    return list(getattr(sys, "orig_argv", None) or [sys.executable, *sys.argv])


def with_flag(command, flag, enabled):
    """The command line with a flag added (once) or removed."""

    command = [part for part in command if part != flag]

    return [*command, flag] if enabled else command


def spawn_relauncher(command=None, cwd=None, log_path=None, pid=None):
    """Start the detached helper that revives the server once this exits."""

    command = command or original_command()

    cwd = str(cwd or Path.cwd())

    log_path = str(log_path or Path(cwd) / "logs" / "server.log")

    kwargs = {}

    if os.name == "nt":
        kwargs["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.DETACHED_PROCESS
            | subprocess.CREATE_NO_WINDOW
        )
    else:
        kwargs["start_new_session"] = True

    return subprocess.Popen(
        [sys.executable, str(HERE / "relaunch.py"),
         str(pid or os.getpid()), cwd, log_path, "--", *command],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, **kwargs
    )


def restart(spawn=spawn_relauncher, shutdown=request_shutdown):
    """Bring the server back under the same command line, then stop this one."""

    spawn()

    shutdown()
