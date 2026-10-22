"""Backups of the database: made automatically every day, listed, checked, downloaded and restored.

A backup is one SQLite file (alerts, accounts, settings; never logins). Kept in a folder next to the
database (IDS_BACKUP_DIR), the newest IDS_BACKUP_KEEP automatic ones. Restoring checks the file first,
keeps a copy of what is being replaced, and signs everyone out but the administrator who asked.
"""
import logging
import os
import re
import sqlite3
import threading
import time
from datetime import datetime

log = logging.getLogger("ids")

KEEP_AUTOMATIC = 7
KEEP_SAFETY = 3
EVERY_SECONDS = 24 * 3600
CHECK_SECONDS = 600

# the largest file accepted for upload (a database of many hundred thousand alerts is a few hundred MB)
MAX_UPLOAD = 512 * 1024 * 1024

# what a real backup of this program must hold
REQUIRED_TABLES = {"alerts", "alert_events", "users", "settings", "audit"}

NAME = re.compile(r"^ids-(auto|manual|before-restore|uploaded)-\d{8}-\d{6}(-\d+)?\.db$")

KINDS = {"auto": "Automatic", "manual": "Manual", "before-restore": "Before a restore", "uploaded": "Uploaded"}


class BackupError(Exception):
    """A problem worth showing to the person, in plain words."""


def check_file(path):
    """Is this a usable backup? Returns {"alerts": n, "users": n}; raises BackupError."""

    try:
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as error:
        raise BackupError(f"that file cannot be opened as a database ({error})")

    try:
        try:
            verdict = db.execute("PRAGMA integrity_check").fetchone()[0]
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        except sqlite3.DatabaseError as error:
            raise BackupError(f"that file is not a readable database ({error})")

        if verdict != "ok":
            raise BackupError("that file is damaged (the database integrity check failed)")

        missing = REQUIRED_TABLES - tables

        if missing:
            raise BackupError("that is not a backup of this program (missing: " + ", ".join(sorted(missing)) + ")")

        return {
            "alerts": db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        }
    finally:
        db.close()


class BackupManager:

    def __init__(self, store, directory, keep=KEEP_AUTOMATIC, clock=time.time):

        self.store = store
        self.directory = directory
        self.keep = max(1, int(keep))
        self.clock = clock
        self.stop = threading.Event()
        self.thread = None
        self.last_error = ""

        os.makedirs(directory, exist_ok=True)

    # -- the files --------------------------------------------------------------------------------------

    def path(self, name):
        """The file for a listed name; anything else (a path, a guess) is refused."""

        if not NAME.match(name or ""):
            raise BackupError("no such backup")

        path = os.path.join(self.directory, name)

        if not os.path.isfile(path):
            raise BackupError("no such backup")

        return path

    def list(self):
        """Newest first: name, kind, size, time."""

        rows = []

        for name in os.listdir(self.directory):

            match = NAME.match(name)

            if not match:
                continue

            stat = os.stat(os.path.join(self.directory, name))

            rows.append({
                "name": name,
                "kind": match.group(1),
                "label": KINDS[match.group(1)],
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "at": stat.st_mtime
            })

        return sorted(rows, key=lambda r: r["at"], reverse=True)

    def create(self, kind="manual"):
        """Write a backup now. Returns its listing row."""

        stamp = datetime.fromtimestamp(self.clock()).strftime("%Y%m%d-%H%M%S")

        name = f"ids-{kind}-{stamp}.db"

        number = 1

        while os.path.exists(os.path.join(self.directory, name)):
            number += 1
            name = f"ids-{kind}-{stamp}-{number}.db"

        path = os.path.join(self.directory, name)

        partial = path + ".part"

        try:
            self.store.backup_to(partial)

            check_file(partial)

            os.replace(partial, path)
        except Exception:

            if os.path.exists(partial):
                os.unlink(partial)

            raise

        self.prune()

        return next(row for row in self.list() if row["name"] == name)

    def prune(self):
        """Old automatic backups and old pre-restore copies go; manual and uploaded ones stay until deleted."""

        for kind, keep in (("auto", self.keep), ("before-restore", KEEP_SAFETY)):

            for row in [r for r in self.list() if r["kind"] == kind][keep:]:
                os.unlink(os.path.join(self.directory, row["name"]))

    def delete(self, name):

        os.unlink(self.path(name))

    def add_upload(self, temporary):
        """Take a file someone uploaded: checked first, then kept. Returns its listing row and what it holds."""

        facts = check_file(temporary)

        stamp = datetime.fromtimestamp(self.clock()).strftime("%Y%m%d-%H%M%S")

        name = f"ids-uploaded-{stamp}.db"

        number = 1

        while os.path.exists(os.path.join(self.directory, name)):
            number += 1
            name = f"ids-uploaded-{stamp}-{number}.db"

        os.replace(temporary, os.path.join(self.directory, name))

        return next(row for row in self.list() if row["name"] == name), facts

    # -- recovery -------------------------------------------------------------------------------------------

    def restore(self, name, keep_session=None):
        """Put a backup back as the live database. A copy of what it replaces is kept first.

        Returns {"restored": name, "safety": the pre-restore copy, "alerts": n, "users": n}.
        """

        path = self.path(name)

        facts = check_file(path)

        safety = self.create("before-restore")

        self.store.restore_from(path, keep_session=keep_session)

        return {"restored": name, "safety": safety["name"], **facts}

    # -- automatic backups --------------------------------------------------------------------------------------

    def due(self):
        """True when there is no automatic or manual backup from the last day."""

        recent = [r for r in self.list() if r["kind"] in ("auto", "manual")]

        return not recent or self.clock() - recent[0]["at"] >= EVERY_SECONDS

    def run_once(self):
        """Make the daily backup if it is due. Never raises: a failure is remembered and logged."""

        try:
            if self.due():
                row = self.create("auto")
                log.info("automatic backup written: %s (%d bytes)", row["name"], row["size"])

            self.last_error = ""
        except Exception as error:
            self.last_error = str(error) or error.__class__.__name__
            log.error("automatic backup failed: %s", self.last_error)

    def start(self):

        def loop():

            # a moment after start-up, then every few minutes check whether a day has passed
            self.stop.wait(30)

            while not self.stop.is_set():
                self.run_once()
                self.stop.wait(CHECK_SECONDS)

        self.thread = threading.Thread(target=loop, name="backups", daemon=True)
        self.thread.start()

    def close(self):

        self.stop.set()
