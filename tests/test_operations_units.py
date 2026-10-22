import json
import logging
import os
import plistlib
import shutil
import subprocess
import sys
import textwrap
import time

import pandas as pd
import pytest
from cryptography.fernet import Fernet

import autostart
import files
import lifecycle
import logbuffer
import relaunch
from jobs import JobBusy, JobManager
from notifier import Notifier, SettingsError, build_settings, masked, runtime_config
from secrets_store import SecretBox
from storage import Store


# -- encrypted secrets ---------------------------------------------------------

def test_secrets_round_trip_and_differ_each_time(tmp_path):

    box = SecretBox(tmp_path / "k.key", env={})

    first, second = box.encrypt("hunter2"), box.encrypt("hunter2")

    assert first != second and first.startswith("enc:") and "hunter2" not in first
    assert box.decrypt(first) == box.decrypt(second) == "hunter2"


def test_plain_values_pass_through_decrypt(tmp_path):

    box = SecretBox(tmp_path / "k.key", env={})

    assert box.decrypt("not encrypted") == "not encrypted"
    assert box.decrypt(None) is None


def test_the_key_file_is_created_once_and_reused(tmp_path):

    path = tmp_path / "sub" / "k.key"

    token = SecretBox(path, env={}).encrypt("x")

    assert path.exists()

    # a new box (a new process) reads the same key
    assert SecretBox(path, env={}).decrypt(token) == "x"

    if os.name != "nt":
        assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_the_key_can_come_from_the_environment(tmp_path):

    key = Fernet.generate_key().decode()

    box = SecretBox(tmp_path / "unused.key", env={"IDS_SECRET_KEY": key})

    token = box.encrypt("x")

    assert not (tmp_path / "unused.key").exists()
    assert SecretBox(tmp_path / "other.key", env={"IDS_SECRET_KEY": key}).decrypt(token) == "x"


def test_a_lost_key_is_reported_not_returned_as_garbage(tmp_path):

    token = SecretBox(tmp_path / "a.key", env={}).encrypt("x")

    with pytest.raises(ValueError, match="cannot be decrypted"):
        SecretBox(tmp_path / "b.key", env={}).decrypt(token)


# -- the in-memory log -------------------------------------------------------------

def make_logger(handler, name="ids.test"):

    logger = logging.getLogger(name)

    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)

    return logger


def test_log_ring_keeps_only_the_newest_lines():

    handler = logbuffer.RingHandler(capacity=3)

    logger = make_logger(handler)

    for i in range(5):
        logger.info("line %s", i)

    assert [r["message"] for r in handler.recent()] == ["line 2", "line 3", "line 4"]


def test_log_levels_and_incremental_reads():

    handler = logbuffer.RingHandler()

    logger = make_logger(handler)

    logger.info("fine")
    logger.warning("careful")
    logger.error("broken")

    assert [r["level"] for r in handler.recent(minimum="WARNING")] == ["WARNING", "ERROR"]

    seen = handler.recent()[-1]["n"]

    logger.info("later")

    assert [r["message"] for r in handler.recent(after=seen)] == ["later"]

    # the limit keeps the newest
    assert len(handler.recent(limit=2)) == 2


def test_access_log_lines_are_left_out():

    handler = logbuffer.RingHandler()

    make_logger(handler, "uvicorn.access").info("GET /api/stats")
    make_logger(handler, "ids.other").info("kept")

    assert [r["message"] for r in handler.recent()] == ["kept"]


# -- uploaded files -------------------------------------------------------------------

@pytest.mark.parametrize("area, name", [
    ("captures", "../x.pcap"), ("captures", "sub/x.pcap"), ("captures", ".hidden.pcap"),
    ("captures", "x.exe"), ("dataset", "x.pcap"), ("captures", "a" * 200 + ".pcap"),
    ("captures", "semi;colon.pcap"), ("nowhere", "x.pcap"), ("captures", "x"),
])
def test_unsafe_or_wrong_file_names_are_refused(area, name):

    with pytest.raises(files.FileError):
        files.check_name(area, name)


@pytest.mark.parametrize("area, name", [
    ("captures", "web.pcap"), ("captures", "Day 1 (copy).pcapng"),
    ("captures", "flows-2026.CSV"), ("dataset", "Monday.pcap_ISCX.csv"),
])
def test_ordinary_names_are_accepted(area, name):

    assert files.check_name(area, name) == name


def test_pcap_magic_numbers(tmp_path):

    from conftest import write_pcap

    write_pcap(tmp_path / "real.pcap", flows=1)

    files.check_pcap(tmp_path / "real.pcap")

    (tmp_path / "fake.pcap").write_bytes(b"MZ\x90\x00 this is not a capture")

    with pytest.raises(files.FileError, match="pcap"):
        files.check_pcap(tmp_path / "fake.pcap")

    (tmp_path / "ng.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)

    files.check_pcap(tmp_path / "ng.pcapng")


def dataset_frame(**extra):

    from feature_extractor import FEATURES

    frame = pd.DataFrame({name: [1, 2, 3] for name in FEATURES})

    frame["Label"] = ["BENIGN", "DDoS", "Web Attack \x96 XSS"]

    for name, value in extra.items():
        frame[name] = value

    return frame


def test_dataset_csv_needs_the_columns_the_model_uses(tmp_path):

    good = tmp_path / "good.csv"

    dataset_frame().to_csv(good, index=False, encoding="latin-1")

    files.check_dataset_csv(good)

    # newer CICFlowMeter spellings and padded names are accepted too
    renamed = dataset_frame().rename(
        columns={"Destination Port": " Dst Port", "Flow Bytes/s": "Flow Byts/s"}
    )

    renamed.to_csv(tmp_path / "alias.csv", index=False, encoding="latin-1")

    files.check_dataset_csv(tmp_path / "alias.csv")

    dataset_frame().drop(columns=["Label"]).to_csv(tmp_path / "nolabel.csv", index=False)

    with pytest.raises(files.FileError, match="Label"):
        files.check_dataset_csv(tmp_path / "nolabel.csv")

    dataset_frame().drop(columns=["Flow Duration", "Fwd IAT Min"]).to_csv(
        tmp_path / "missing.csv", index=False
    )

    with pytest.raises(files.FileError, match="Flow Duration"):
        files.check_dataset_csv(tmp_path / "missing.csv")

    (tmp_path / "empty.csv").write_text("")

    with pytest.raises(files.FileError, match="readable"):
        files.check_dataset_csv(tmp_path / "empty.csv")


def test_label_counts_merge_web_attack_variants(tmp_path):

    path = tmp_path / "d.csv"

    frame = pd.concat([dataset_frame(), dataset_frame()], ignore_index=True)

    frame.to_csv(path, index=False, encoding="latin-1")

    assert files.label_counts(path) == {"BENIGN": 2, "DDoS": 2, "Web Attack": 2}


def test_listing_hides_partial_hidden_and_foreign_files(tmp_path, monkeypatch):

    monkeypatch.setenv("IDS_DATASET_DIR", str(tmp_path / "ds"))

    (tmp_path / "ds").mkdir()

    for name in ("a.csv", ".b.csv.part", "c.txt"):
        (tmp_path / "ds" / name).write_text("x")

    assert [f["name"] for f in files.listing("dataset", tmp_path)] == ["a.csv"]

    (tmp_path / "x.pcap").write_bytes(b"1234")
    (tmp_path / ".y.pcap.part").write_bytes(b"1234")

    listing = files.listing("captures", tmp_path)

    assert [f["name"] for f in listing] == ["x.pcap"] and listing[0]["size"] == 4

    assert files.listing("captures", tmp_path / "missing") == []


def test_upload_limit_comes_from_the_environment():

    assert files.max_bytes({}) == files.DEFAULT_MAX_MB * 1024 * 1024
    assert files.max_bytes({"IDS_MAX_UPLOAD_MB": "5"}) == 5 * 1024 * 1024


# -- background jobs ---------------------------------------------------------------

@pytest.fixture
def scripts(tmp_path):

    def write(name, body):
        (tmp_path / name).write_text(textwrap.dedent(body))

    write("ok.py", """
        print("step 1"); print("step 2"); print("done")
    """)

    write("bad.py", """
        import sys
        print("about to fail"); sys.exit(3)
    """)

    write("slow.py", """
        import time
        print("started", flush=True)
        time.sleep(60)
    """)

    return tmp_path


KINDS = {
    "ok": {"script": "ok.py", "title": "OK", "needs_dataset": False, "reloads_model": False},
    "bad": {"script": "bad.py", "title": "Bad", "needs_dataset": False, "reloads_model": False},
    "slow": {"script": "slow.py", "title": "Slow", "needs_dataset": False, "reloads_model": False},
}


def manager(scripts, **callbacks):

    return JobManager(str(scripts), kinds=KINDS, **callbacks)


def test_a_job_collects_its_output_and_reports_success(scripts):

    seen, succeeded = [], []

    jobs = manager(scripts, on_change=lambda j: seen.append(j.state),
                   on_success=lambda j: succeeded.append(j.id))

    job = jobs.start("ok", actor="alice")

    assert jobs.wait(job) == "succeeded"

    assert job.returncode == 0 and job.actor == "alice"
    assert list(job.lines) == ["step 1", "step 2", "done"]
    assert seen == ["running", "succeeded"]
    assert succeeded == [job.id]


def test_a_failing_job_is_reported_and_does_not_count_as_success(scripts):

    succeeded = []

    jobs = manager(scripts, on_success=succeeded.append)

    job = jobs.start("bad")

    assert jobs.wait(job) == "failed"

    assert job.returncode == 3 and "about to fail" in job.lines
    assert succeeded == []


def test_only_one_job_runs_at_a_time_and_it_can_be_cancelled(scripts):

    jobs = manager(scripts)

    slow = jobs.start("slow")

    deadline = time.time() + 10

    while not slow.lines and time.time() < deadline:
        time.sleep(0.05)

    assert jobs.running() is slow

    with pytest.raises(JobBusy):
        jobs.start("ok")

    assert jobs.cancel(slow.id) is True

    assert jobs.wait(slow) == "cancelled"

    assert jobs.cancel(slow.id) is False
    assert jobs.running() is None

    # free again
    assert jobs.wait(jobs.start("ok")) == "succeeded"


def test_unknown_jobs_cannot_be_started(scripts):

    with pytest.raises(ValueError, match="unknown job"):
        manager(scripts).start("rm -rf /")


def test_output_can_be_read_incrementally(scripts):

    jobs = manager(scripts)

    job = jobs.start("ok")

    jobs.wait(job)

    everything = job.tail()

    assert everything["output"] == ["step 1", "step 2", "done"] and everything["from"] == 0

    assert job.tail(after=2)["output"] == ["done"]
    assert job.tail(after=99)["output"] == []


def test_job_history_is_newest_first_and_capped(scripts, monkeypatch):

    import jobs as jobs_module

    monkeypatch.setattr(jobs_module, "KEEP_JOBS", 3)

    jobs = manager(scripts)

    for _ in range(5):
        jobs.wait(jobs.start("ok"))

    assert [j["id"] for j in jobs.recent()] == [5, 4, 3]


def test_a_missing_script_fails_cleanly(tmp_path):

    jobs = JobManager(str(tmp_path), kinds={
        "x": {"script": "nope.py", "title": "X", "needs_dataset": False, "reloads_model": False}
    })

    job = jobs.start("x")

    assert jobs.wait(job) == "failed"


def test_a_job_whose_follow_up_step_fails_is_reported_as_failed(scripts):

    def explode(job):
        raise RuntimeError("could not reload")

    jobs = manager(scripts, on_success=explode)

    job = jobs.start("ok")

    assert jobs.wait(job) == "failed"

    assert job.returncode == 0
    assert any("follow-up step failed: could not reload" in line for line in job.lines)


def test_the_follow_up_step_has_finished_before_success_is_reported(scripts):
    """Nobody may see 'succeeded' while the new model is still being loaded."""

    seen_by_the_step = []

    def step(job):
        seen_by_the_step.append(job.state)
        time.sleep(0.5)

    jobs = manager(scripts, on_success=step)

    job = jobs.start("ok")

    deadline = time.time() + 20

    while not seen_by_the_step and time.time() < deadline:
        time.sleep(0.02)

    # while the step runs, the job still says it is running
    assert job.state == "running"

    assert jobs.wait(job) == "succeeded"

    assert seen_by_the_step == ["running"]


# -- start at login ------------------------------------------------------------------

COMMAND = ["C:/Python312/python.exe", "serve.py", "--port", "8000"]


def test_secrets_are_never_carried_into_login_tasks():

    env = autostart.carried_environment({
        "IDS_DB": "x.db", "IDS_DATA_DIR": "caps", "IDS_ADMIN_TOKEN": "secret",
        "IDS_API_KEY": "secret", "IDS_SECRET_KEY": "secret", "PATH": "/bin", "IDS_MODEL": ""
    })

    assert env == {"IDS_DB": "x.db", "IDS_DATA_DIR": "caps"}


def test_windows_script_registers_a_logon_task():

    script = autostart.windows_register_script(
        COMMAND, "C:/Users/me/IDS", {"IDS_DB": "C:/data/ids.db"}, "C:/logs/server.log"
    )

    assert "Register-ScheduledTask -TaskName 'BayesianIDS-Login'" in script
    assert "-AtLogOn" in script and "-RestartCount 3" in script
    assert "IDS_ADMIN_TOKEN" not in script


@pytest.mark.skipif(
    not (sys.platform == "win32" and shutil.which("powershell")),
    reason="needs Windows PowerShell"
)
def test_windows_script_quotes_awkward_paths_correctly():
    """Run the script's first lines in PowerShell and inspect the command it
    builds: apostrophes in a path must survive two levels of quoting."""

    script = autostart.windows_register_script(
        COMMAND, "C:/Users/O'Brien/IDS", {"IDS_DB": "C:/data/it's.db"},
        "C:/logs/server.log"
    )

    # the whole script must at least parse
    parse = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]"
         "::ParseInput($env:SCRIPT,[ref]$t,[ref]$e);$e.Count"],
        capture_output=True, text=True, env={**os.environ, "SCRIPT": script}
    )

    assert parse.stdout.strip() == "0", parse.stdout + parse.stderr

    # evaluate only the assignment of the inner command and print it
    first_lines = "\n".join(script.splitlines()[:2])

    shown = subprocess.run(
        ["powershell", "-NoProfile", "-Command", first_lines + "\n$inner"],
        capture_output=True, text=True
    )

    inner = shown.stdout.strip()

    assert "$env:IDS_DB = 'C:/data/it''s.db'" in inner
    assert "Set-Location 'C:/Users/O''Brien/IDS'" in inner
    assert "serve.py" in inner and "C:/logs/server.log" in inner

    # and that inner command is itself valid PowerShell
    inner_parse = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]"
         "::ParseInput($env:INNER,[ref]$t,[ref]$e);$e.Count"],
        capture_output=True, text=True, env={**os.environ, "INNER": inner}
    )

    assert inner_parse.stdout.strip() == "0", inner


def test_systemd_unit_has_the_command_directory_and_environment():

    unit = autostart.systemd_unit(
        ["/usr/bin/python3", "serve.py", "--host", "127.0.0.1"], "/home/me/ids",
        {"IDS_DB": "/home/me/ids.db"}
    )

    assert "WorkingDirectory=/home/me/ids" in unit
    assert "ExecStart=/usr/bin/python3 serve.py --host 127.0.0.1" in unit
    assert "Environment=IDS_DB=/home/me/ids.db" in unit
    assert "WantedBy=default.target" in unit and "Restart=on-failure" in unit


def test_launch_agent_is_a_valid_plist():

    data = plistlib.loads(autostart.launch_agent(
        ["/usr/bin/python3", "serve.py"], "/Users/me/ids", {"IDS_DB": "x"}, "/tmp/s.log"
    ))

    assert data["Label"] == autostart.AGENT_LABEL
    assert data["ProgramArguments"] == ["/usr/bin/python3", "serve.py"]
    assert data["RunAtLoad"] is True and data["WorkingDirectory"] == "/Users/me/ids"


class FakeRun:

    def __init__(self, stdout="", returncode=0, stderr=""):

        self.calls = []
        self.result = subprocess.CompletedProcess([], returncode, stdout, stderr)

    def __call__(self, command, **kwargs):

        self.calls.append(command)

        return self.result


def test_linux_enable_writes_the_user_unit_and_enables_it(tmp_path):

    run = FakeRun()

    linux = autostart.Autostart("linux", run, tmp_path, {"IDS_DB": "i.db"})

    assert linux.supported and linux.enabled() is False

    linux.enable(COMMAND, "/srv/ids", "/srv/ids/logs/server.log")

    unit = (tmp_path / ".config/systemd/user/bayesian-ids.service").read_text()

    assert "Environment=IDS_DB=i.db" in unit

    assert ["systemctl", "--user", "enable", "bayesian-ids.service"] in run.calls

    assert linux.enabled() is True

    linux.disable()

    assert not (tmp_path / ".config/systemd/user/bayesian-ids.service").exists()
    assert linux.enabled() is False


def test_linux_enable_reports_systemd_failures(tmp_path):

    linux = autostart.Autostart("linux", FakeRun(returncode=1, stderr="no user bus"), tmp_path, {})

    with pytest.raises(RuntimeError, match="no user bus"):
        linux.enable(COMMAND, "/srv", "/srv/log")


def test_macos_enable_writes_and_loads_the_launch_agent(tmp_path):

    run = FakeRun()

    mac = autostart.Autostart("darwin", run, tmp_path, {})

    mac.enable(COMMAND, "/Users/me/ids", "/tmp/s.log")

    path = tmp_path / "Library/LaunchAgents/com.bayesian-ids.plist"

    assert path.exists() and mac.enabled()
    assert ["launchctl", "load", "-w", str(path)] in run.calls

    mac.disable()

    assert not path.exists()


def test_windows_enabled_reads_the_task_state_and_reports_failures(tmp_path):

    assert autostart.Autostart("win32", FakeRun("yes\n"), tmp_path, {}).enabled() is True
    assert autostart.Autostart("win32", FakeRun("no\n"), tmp_path, {}).enabled() is False

    broken = autostart.Autostart("win32", FakeRun(returncode=1, stderr="Access is denied"), tmp_path, {})

    with pytest.raises(RuntimeError, match="Access is denied"):
        broken.enable(COMMAND, "C:/ids", "C:/ids/logs/server.log")


def test_unsupported_platforms_say_so(tmp_path):

    other = autostart.Autostart("freebsd13", FakeRun(), tmp_path, {})

    assert not other.supported and other.enabled() is False

    with pytest.raises(RuntimeError, match="not supported"):
        other.enable(COMMAND, "/x", "/y")


# -- restarting ---------------------------------------------------------------------

def test_restart_starts_the_replacement_before_shutting_down():

    order = []

    lifecycle.restart(spawn=lambda: order.append("spawn"),
                      shutdown=lambda: order.append("shutdown"))

    assert order == ["spawn", "shutdown"]


def test_shutdown_asks_the_registered_server_to_exit(monkeypatch):

    class Server:
        should_exit = False

    server = Server()

    monkeypatch.setattr(lifecycle, "SERVER", server)

    lifecycle.request_shutdown()

    assert server.should_exit is True


def test_the_relauncher_gets_the_pid_directory_log_and_original_command(monkeypatch, tmp_path):

    captured = {}

    class FakePopen:

        def __init__(self, command, **kwargs):
            captured["command"] = command
            captured["kwargs"] = kwargs

    monkeypatch.setattr(lifecycle.subprocess, "Popen", FakePopen)

    lifecycle.spawn_relauncher(
        command=["python", "-m", "uvicorn", "api:app", "--port", "8000"],
        cwd=tmp_path, log_path=tmp_path / "s.log", pid=4242
    )

    command = captured["command"]

    assert command[1].endswith("relaunch.py")
    assert command[2:5] == ["4242", str(tmp_path), str(tmp_path / "s.log")]
    assert command[5:] == ["--", "python", "-m", "uvicorn", "api:app", "--port", "8000"]


def test_the_original_command_includes_module_launches():

    assert lifecycle.original_command()[0] == sys.executable or lifecycle.original_command()


def test_relaunch_waits_for_the_old_process_then_starts_the_command(tmp_path):
    """Real processes: the 'old server' sleeps briefly; the new one writes a file."""

    old = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1.5)"])

    marker = tmp_path / "started.txt"

    began = time.time()

    relaunch.main([
        str(old.pid), str(tmp_path), str(tmp_path / "relaunch.log"), "--",
        sys.executable, "-c",
        f"open(r'{marker}', 'w').write('hello'); print('ran')"
    ])

    waited = time.time() - began

    # it did not start the new command until the old one had gone
    assert waited >= 1.0

    deadline = time.time() + 15

    while not marker.exists() and time.time() < deadline:
        time.sleep(0.1)

    assert marker.read_text() == "hello"

    assert old.poll() is not None


# -- notification settings --------------------------------------------------------------

@pytest.fixture
def store(tmp_path):

    store = Store(str(tmp_path / "n.db"))

    yield store

    store.close()


@pytest.fixture
def box(tmp_path):

    return SecretBox(tmp_path / "n.key", env={})


GOOD = {
    "min_risk": "High", "sources": ["capture", "api"], "window_seconds": 10,
    "base_url": "https://ids.example.com/",
    "webhook": {"enabled": True, "format": "slack", "url": "https://hooks.slack.com/services/T/B/SECRET"},
    "email": {"enabled": True, "host": "smtp.example.com", "port": 587, "starttls": True,
              "username": "ids", "password": "smtp-secret", "from": "ids@example.com",
              "to": ["soc@example.com"]}
}


def test_settings_are_stored_encrypted_and_shown_masked(box):

    stored = build_settings(GOOD, None, box)

    dump = json.dumps(stored)

    assert "SECRET" not in dump and "smtp-secret" not in dump
    assert stored["base_url"] == "https://ids.example.com"

    shown = json.dumps(masked(stored))

    assert "SECRET" not in shown and "smtp-secret" not in shown and "enc:" not in shown
    assert masked(stored)["email"]["has_password"] is True

    config = runtime_config(stored, box)

    assert config["webhook"]["url"].endswith("SECRET")
    assert config["email"]["password"] == "smtp-secret"


def test_leaving_a_secret_out_keeps_the_stored_one(box):

    stored = build_settings(GOOD, None, box)

    update = json.loads(json.dumps(GOOD))

    del update["webhook"]["url"]
    del update["email"]["password"]

    update["min_risk"] = "Critical"

    again = build_settings(update, stored, box)

    assert again["min_risk"] == "Critical"
    assert again["webhook"]["url"] == stored["webhook"]["url"]
    assert again["email"]["password"] == stored["email"]["password"]

    # an explicit empty password clears it
    update["email"]["password"] = ""

    assert build_settings(update, stored, box)["email"]["password"] is None


@pytest.mark.parametrize("change, message", [
    ({"min_risk": "Low"}, "min_risk"),
    ({"sources": []}, "sources"),
    ({"sources": ["telepathy"]}, "sources"),
    ({"window_seconds": 0}, "window"),
    ({"window_seconds": "ten"}, "window"),
    ({"base_url": "ftp://x"}, "address"),
])
def test_bad_general_settings_are_refused(box, change, message):

    with pytest.raises(SettingsError, match=message):
        build_settings({**GOOD, **change}, None, box)


@pytest.mark.parametrize("path, value, message", [
    (("webhook", "url"), "javascript:alert(1)", "http"),
    (("webhook", "format"), "fax", "format"),
    (("email", "host"), "", "SMTP server"),
    (("email", "port"), 70000, "port"),
    (("email", "to"), [], "recipient"),
    (("email", "to"), ["not-an-address"], "recipient"),
    (("email", "from"), "nobody", "sender"),
])
def test_bad_channel_settings_are_refused(box, path, value, message):

    bad = json.loads(json.dumps(GOOD))

    bad[path[0]][path[1]] = value

    with pytest.raises(SettingsError, match=message):
        build_settings(bad, None, box)


def test_an_enabled_webhook_needs_a_url_the_first_time(box):

    bad = json.loads(json.dumps(GOOD))

    del bad["webhook"]["url"]

    with pytest.raises(SettingsError, match="needs a URL"):
        build_settings(bad, None, box)


def test_disabled_channels_are_dropped(box):

    only_mail = {**GOOD, "webhook": {"enabled": False, "url": "https://x"}}

    stored = build_settings(only_mail, None, box)

    assert stored["webhook"] is None and stored["email"]


def test_saved_settings_survive_a_restart_and_beat_the_file(store, box, tmp_path, monkeypatch):

    (tmp_path / "notify.json").write_text(json.dumps({"min_risk": "Medium"}))

    monkeypatch.setenv("IDS_NOTIFY_CONFIG", str(tmp_path / "notify.json"))

    first = Notifier(store, box=box)

    assert first.managed is False and first.config["min_risk"] == "Medium"
    assert first.settings() == {"source": "none", "settings": None}

    first.save_managed(GOOD)

    assert first.managed and first.config["min_risk"] == "High"
    assert first.status()["source"] == "dashboard"

    # a fresh process picks the saved settings up
    second = Notifier(store, box=box)

    assert second.managed and second.channels() == ["webhook", "email"]
    assert second.config["webhook"]["url"].endswith("SECRET")

    assert second.settings()["source"] == "dashboard"

    # and the secret is not readable in the database itself
    raw = store.db.execute("SELECT value FROM settings WHERE key = 'notify_config'").fetchone()[0]

    assert "SECRET" not in raw and "smtp-secret" not in raw


# -- audit trail and backups -----------------------------------------------------------

def test_audit_entries_are_listed_newest_first_and_pruned(store):

    for i in range(5):
        store.add_audit("alice", f"action {i}", f"detail {i}")

    entries = store.list_audit()

    assert [e["action"] for e in entries] == [f"action {i}" for i in (4, 3, 2, 1, 0)]
    assert entries[0]["actor"] == "alice"

    older = store.list_audit(limit=2, before_id=entries[2]["id"])

    assert [e["action"] for e in older] == ["action 1", "action 0"]

    store.prune_audit(keep=2)

    assert [e["action"] for e in store.list_audit()] == ["action 4", "action 3"]


def test_backup_is_a_complete_consistent_copy(store, tmp_path, make_alert):

    store.add_alerts([make_alert(), make_alert()])
    store.set_setting("api_ingest_enabled", False)
    store.add_user("root", "hash", "admin")
    store.add_session("a-session-token-hash", "root", "2999-01-01T00:00:00")

    target = tmp_path / "copy.db"

    store.backup_to(str(target))

    # the live database keeps its session; the copy has none, anywhere in the file
    assert store.get_session("a-session-token-hash")["username"] == "root"
    assert b"a-session-token-hash" not in target.read_bytes()

    copy = Store(str(target))

    try:
        assert len(copy.list_alerts(status="all")) == 2
        assert copy.get_setting("api_ingest_enabled") is False
        assert copy.get_user("root")["role"] == "admin"
        assert copy.get_session("a-session-token-hash") is None
    finally:
        copy.close()


# -- a restored backup without its key, or with damaged secrets -------------------------

def saved_notifier(store, box):

    notifier = Notifier(store, box=box)

    notifier.save_managed(GOOD)

    return notifier


def test_a_missing_key_does_not_stop_the_server_and_says_what_to_do(store, box, tmp_path):

    saved_notifier(store, box)

    # a restored backup: same database, no key file, so a new key appears
    new_box = SecretBox(tmp_path / "different.key", env={})

    restored = Notifier(store, box=new_box)

    assert restored.channels() == []
    assert restored.problem and "cannot be read" in restored.problem
    assert restored.status()["problem"] == restored.problem
    assert restored.settings()["problem"] == restored.problem

    # the form can still show that settings exist, without any secret
    shown = restored.settings()["settings"]

    assert shown["webhook"]["has_url"] and "SECRET" not in json.dumps(shown)

    # nothing is sent, and nothing is queued
    restored.submit([{"source": "capture", "risk": "Critical", "id": 1}])

    assert restored.pending == []


def test_the_problem_is_fixed_by_entering_the_secrets_again(store, box, tmp_path):

    saved_notifier(store, box)

    restored = Notifier(store, box=SecretBox(tmp_path / "different.key", env={}))

    # leaving the secrets blank cannot work: the stored ones are unreadable
    blank = json.loads(json.dumps(GOOD))

    del blank["webhook"]["url"]
    del blank["email"]["password"]

    with pytest.raises(SettingsError, match="enter"):
        restored.save_managed(blank)

    assert restored.problem

    # entering them again repairs everything
    restored.save_managed(GOOD)

    assert restored.problem is None
    assert restored.channels() == ["webhook", "email"]

    assert Notifier(store, box=restored.box).problem is None


def test_damaged_ciphertext_is_reported_the_same_way(store, box):

    saved_notifier(store, box)

    stored = store.get_setting("notify_config")

    stored["webhook"]["url"] = stored["webhook"]["url"][:-8] + "AAAAAAAA"

    store.set_setting("notify_config", stored)

    broken = Notifier(store, box=box)

    assert broken.problem and broken.channels() == []


def test_a_key_from_the_environment_decrypts_what_it_encrypted(store, tmp_path):

    key = Fernet.generate_key().decode()

    first = Notifier(store, box=SecretBox(tmp_path / "unused.key", env={"IDS_SECRET_KEY": key}))

    first.save_managed(GOOD)

    # the same environment key in a fresh process, with no key file at all
    second = Notifier(store, box=SecretBox(tmp_path / "other.key", env={"IDS_SECRET_KEY": key}))

    assert second.problem is None and second.channels() == ["webhook", "email"]
    assert not (tmp_path / "other.key").exists()
