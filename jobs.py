"""
Long-running maintenance tasks started from the dashboard: retraining the
model, evaluating it, comparing it with baseline models.

Each runs the project's own script in a child process (isolated memory,
cancellable) and keeps its output so the dashboard can show progress.
Only the scripts listed in KINDS can be run, and only one job at a time.
"""
import os
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime

KINDS = {
    "train": {
        "script": "train_model.py",
        "title": "Retrain the model",
        "needs_dataset": True,
        "reloads_model": True
    },
    "evaluate": {
        "script": "evaluate_model.py",
        "title": "Evaluate the model on held-out data",
        "needs_dataset": True,
        "reloads_model": False
    },
    "compare": {
        "script": "compare_baselines.py",
        "title": "Compare with baseline models",
        "needs_dataset": True,
        "reloads_model": False
    }
}

MAX_LINES = 3000

KEEP_JOBS = 20


class JobBusy(RuntimeError):
    """Another job is still running."""


class Job:

    def __init__(self, job_id, kind, actor, title):

        self.id = job_id
        self.kind = kind
        self.title = title
        self.actor = actor
        self.state = "running"
        self.started_at = datetime.now().isoformat(timespec="seconds")
        self.finished_at = None
        self.returncode = None
        self.lines = deque(maxlen=MAX_LINES)
        self.total_lines = 0
        self.process = None
        self.cancelled = False

    def summary(self):

        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "actor": self.actor,
            "state": self.state,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "returncode": self.returncode,
            "lines": self.total_lines
        }

    def tail(self, after=0):
        """Output lines numbered from `after` (0-based) onwards."""

        first = self.total_lines - len(self.lines)

        start = max(after, first)

        return {
            **self.summary(),
            "from": start,
            "output": list(self.lines)[start - first:]
        }


class JobManager:

    def __init__(self, project_dir, python=None, on_change=None,
                 on_success=None, kinds=None):
        """
        on_change(job): state changed (started / finished)
        on_success(job): the job exited 0
        """

        self.project_dir = project_dir
        self.python = python or sys.executable
        self.on_change = on_change
        self.on_success = on_success
        self.kinds = kinds or KINDS

        self.lock = threading.Lock()
        self.jobs = {}
        self.counter = 0

    def running(self):

        with self.lock:
            return next((j for j in self.jobs.values() if j.state == "running"), None)

    def start(self, kind, actor="system", args=()):

        if kind not in self.kinds:
            raise ValueError(f"unknown job: {kind}")

        with self.lock:

            if any(j.state == "running" for j in self.jobs.values()):
                raise JobBusy("another job is still running")

            self.counter += 1

            job = Job(self.counter, kind, actor, self.kinds[kind]["title"])

            self.jobs[job.id] = job

            # keep the list short
            for old in sorted(self.jobs)[:-KEEP_JOBS]:
                del self.jobs[old]

        script = os.path.join(self.project_dir, self.kinds[kind]["script"])

        env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"}

        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        try:
            job.process = subprocess.Popen(
                [self.python, script, *args],
                cwd=self.project_dir, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
                creationflags=flags
            )
        except OSError as error:
            self.finish(job, "failed", None, f"could not start: {error}")
            return job

        threading.Thread(
            target=self.watch, args=(job,), name=f"job-{job.id}", daemon=True
        ).start()

        if self.on_change:
            self.on_change(job)

        return job

    def watch(self, job):
        """Collect output until the process ends, then settle the state."""

        for line in job.process.stdout:

            job.lines.append(line.rstrip())
            job.total_lines += 1

        returncode = job.process.wait()

        if job.cancelled:
            return self.finish(job, "cancelled", returncode)

        if returncode != 0:
            return self.finish(job, "failed", returncode)

        # Anything that has to happen because the job worked (loading the new
        # model) is done before it is reported as finished, so nobody sees a
        # success that has not taken effect yet
        if self.on_success:

            try:
                self.on_success(job)
            except Exception as error:
                job.lines.append(f"finished, but the follow-up step failed: {error}")
                job.total_lines += 1

                return self.finish(job, "failed", returncode)

        self.finish(job, "succeeded", returncode)

    def finish(self, job, state, returncode, message=None):

        if message:
            job.lines.append(message)
            job.total_lines += 1

        job.state = state
        job.returncode = returncode
        job.finished_at = datetime.now().isoformat(timespec="seconds")

        if self.on_change:
            self.on_change(job)

    def cancel(self, job_id):
        """Stop a running job; returns False if it is not running."""

        job = self.jobs.get(job_id)

        if not job or job.state != "running" or not job.process:
            return False

        job.cancelled = True

        job.process.terminate()

        try:
            job.process.wait(5)
        except subprocess.TimeoutExpired:
            job.process.kill()

        return True

    def get(self, job_id):

        return self.jobs.get(job_id)

    def recent(self):

        return [j.summary() for j in sorted(self.jobs.values(), key=lambda j: -j.id)]

    def wait(self, job, seconds=60):
        """Block until a job has finished (tests)."""

        deadline = time.time() + seconds

        while job.state == "running" and time.time() < deadline:
            time.sleep(0.05)

        return job.state
