"""
Helper that brings the server back after the dashboard's Restart button.

    python relaunch.py PID CWD LOGFILE -- COMMAND ARG...

The server starts this detached, then shuts down. This waits until the old
process (PID) has gone, so the port is free, and then starts COMMAND in CWD,
appending its output to LOGFILE. It is deliberately separate from the server:
it must outlive it.
"""
import os
import subprocess
import sys
import time

WAIT_SECONDS = 60


def wait_for_exit(pid, seconds=WAIT_SECONDS):
    """Block until the process is gone (or the time is up)."""

    if os.name == "nt":

        import ctypes

        kernel = ctypes.windll.kernel32

        SYNCHRONIZE = 0x00100000

        handle = kernel.OpenProcess(SYNCHRONIZE, False, pid)

        if handle:
            kernel.WaitForSingleObject(handle, int(seconds * 1000))
            kernel.CloseHandle(handle)

        return

    deadline = time.time() + seconds

    while time.time() < deadline:

        try:
            os.kill(pid, 0)
        except OSError:
            return

        time.sleep(0.2)


def start_detached(command, cwd, log_path):

    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)

    log = open(log_path, "ab")

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
        command, cwd=cwd, stdin=subprocess.DEVNULL,
        stdout=log, stderr=subprocess.STDOUT, **kwargs
    )


def main(argv):

    separator = argv.index("--")

    pid, cwd, log_path = int(argv[0]), argv[1], argv[2]

    command = argv[separator + 1:]

    wait_for_exit(pid)

    # let the operating system release the listening socket
    time.sleep(0.5)

    start_detached(command, cwd, log_path)


if __name__ == "__main__":

    main(sys.argv[1:])
