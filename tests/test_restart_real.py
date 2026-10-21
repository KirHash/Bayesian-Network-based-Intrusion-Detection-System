"""
The Restart button for real: a server process is started, asked to restart
over HTTP, and a different process must answer on the same port afterwards.
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

from conftest import ROOT, needs_model

pytestmark = [pytest.mark.slow, needs_model]


def free_port():

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def fetch(port, path, method="GET"):

    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)

    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def wait_until(check, seconds=90):

    deadline = time.time() + seconds

    while time.time() < deadline:

        try:
            value = check()

            if value:
                return value
        except Exception:
            pass

        time.sleep(0.5)

    return None


def test_restart_brings_a_new_process_up_on_the_same_port(tmp_path):

    port = free_port()

    env = {
        **os.environ,
        "IDS_DB": str(tmp_path / "ids.db"),
        "IDS_DATA_DIR": str(tmp_path / "captures"),
        "IDS_MODEL": str(ROOT / "bayesian_ids.pkl"),
        "PYTHONUNBUFFERED": "1"
    }

    first = subprocess.Popen(
        [sys.executable, str(ROOT / "serve.py"), "--port", str(port)],
        cwd=tmp_path, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    second_pid = None

    try:
        assert wait_until(lambda: fetch(port, "/api/healthz")["status"] == "ok"), "server did not start"

        before = fetch(port, "/api/server")

        assert before["pid"] == first.pid

        assert fetch(port, "/api/server/restart", "POST") == {"restarting": True}

        # the old process exits...
        assert wait_until(lambda: first.poll() is not None, 60), "old server did not stop"

        # ...and another one answers on the same port
        def replaced():

            info = fetch(port, "/api/server")

            return info if info["pid"] != first.pid else None

        after = wait_until(replaced, 90)

        assert after is not None, "no server came back"

        second_pid = after["pid"]

        assert after["command"] == before["command"]

        # it started fresh, and its output is kept in the log file
        assert after["uptime_seconds"] < before["uptime_seconds"] + 90

        assert (tmp_path / "logs" / "server.log").exists()

        assert fetch(port, "/api/healthz")["status"] == "ok"

    finally:

        if first.poll() is None:
            first.kill()

        if second_pid:

            try:
                os.kill(second_pid, signal.SIGTERM)
            except OSError:
                pass
