"""
SQLite persistence for alerts, their handling history, traffic counters
and the notification log.

One connection guarded by a lock: the API calls in from worker threads,
and SQLite in WAL mode handles this volume (thousands of alerts per
second in demo mode) comfortably.
"""
import json
import sqlite3
import threading
from datetime import datetime

STATUSES = ["new", "investigating", "resolved", "false_positive"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    source TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk TEXT NOT NULL,
    probability REAL NOT NULL,
    surprise REAL,
    label TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    status TEXT NOT NULL DEFAULT 'new',
    assignee TEXT,
    note TEXT,
    updated_at TEXT NOT NULL,
    posterior TEXT,
    features TEXT,
    forest REAL
);
CREATE INDEX IF NOT EXISTS alerts_status ON alerts(status, id);
CREATE INDEX IF NOT EXISTS alerts_source ON alerts(source, id);
CREATE INDEX IF NOT EXISTS alerts_type ON alerts(attack_type);

CREATE TABLE IF NOT EXISTS alert_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    time TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS events_alert ON alert_events(alert_id);

CREATE TABLE IF NOT EXISTS traffic (
    minute TEXT NOT NULL,
    source TEXT NOT NULL,
    flows INTEGER NOT NULL,
    alerts INTEGER NOT NULL,
    PRIMARY KEY (minute, source)
);

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_login TEXT,
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_step INTEGER NOT NULL DEFAULT 0,
    recovery TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    client TEXT
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS push_subscriptions (
    endpoint TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    channel TEXT NOT NULL,
    ok INTEGER NOT NULL,
    alerts INTEGER NOT NULL,
    detail TEXT
);
"""

# Columns returned in list views (the heavy JSON stays in the detail view)
LIST_COLUMNS = (
    "id, time, source, attack_type, reason, risk, probability, surprise, "
    "label, src_ip, dst_ip, dst_port, status, assignee, note, updated_at"
)


def now():

    return datetime.now().isoformat(timespec="seconds")


class Store:

    def __init__(self, path="ids.db"):

        self.lock = threading.Lock()

        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row

        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.execute("PRAGMA foreign_keys=ON")
            self._migrate()

    def _migrate(self):
        """Create what is missing and bring an older database up to date (caller holds the lock)."""

        self.db.executescript(SCHEMA)

        # databases made before the forest's second opinion existed
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(alerts)")}

        if "forest" not in columns:
            self.db.execute("ALTER TABLE alerts ADD COLUMN forest REAL")

        # databases made before two-factor sign-in and the session list existed
        for column, kind in (
            ("totp_secret", "TEXT"), ("totp_enabled", "INTEGER NOT NULL DEFAULT 0"),
            ("totp_step", "INTEGER NOT NULL DEFAULT 0"), ("recovery", "TEXT")
        ):
            if column not in {row[1] for row in self.db.execute("PRAGMA table_info(users)")}:
                self.db.execute(f"ALTER TABLE users ADD COLUMN {column} {kind}")

        if "client" not in {row[1] for row in self.db.execute("PRAGMA table_info(sessions)")}:
            self.db.execute("ALTER TABLE sessions ADD COLUMN client TEXT")

        self.db.commit()

    # -- writes ----------------------------------------------------------

    def add_alerts(self, records):
        """Insert alert dicts; returns their new ids in order."""

        if not records:
            return []

        with self.lock:

            first = self.db.execute(
                "SELECT COALESCE(MAX(id), 0) FROM alerts"
            ).fetchone()[0]

            self.db.executemany(
                "INSERT INTO alerts (time, source, attack_type, reason, risk,"
                " probability, surprise, label, src_ip, dst_ip, dst_port,"
                " updated_at, posterior, features, forest)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        r["time"], r["source"], r["attack_type"], r["reason"],
                        r["risk"], r["probability"], r.get("surprise"),
                        r.get("label"), r.get("src_ip"), r.get("dst_ip"),
                        r.get("dst_port"), r["time"],
                        json.dumps(r.get("posterior")),
                        json.dumps(r.get("features")),
                        r.get("forest")
                    )
                    for r in records
                ]
            )

            self.db.commit()

        return list(range(first + 1, first + len(records) + 1))

    def add_traffic(self, source, flows, alerts):

        minute = now()[:16]

        with self.lock:

            self.db.execute(
                "INSERT INTO traffic (minute, source, flows, alerts)"
                " VALUES (?,?,?,?)"
                " ON CONFLICT(minute, source) DO UPDATE SET"
                " flows = flows + excluded.flows,"
                " alerts = alerts + excluded.alerts",
                (minute, source, flows, alerts)
            )

            self.db.commit()

    def update_alert(self, alert_id, status=None, assignee=None, note=None,
                     actor="analyst"):
        """Change handling fields; returns the new row or None if unknown."""

        if status is not None and status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")

        with self.lock:

            row = self.db.execute(
                "SELECT status, assignee, note FROM alerts WHERE id = ?",
                (alert_id,)
            ).fetchone()

            if row is None:
                return None

            events = []

            if status is not None and status != row["status"]:
                events.append((
                    "status", f"{row['status']} -> {status}"
                ))

            if assignee is not None and assignee != (row["assignee"] or ""):
                events.append(("assigned", assignee or "unassigned"))

            if note is not None and note != (row["note"] or ""):
                events.append(("note", note))

            if events:

                self.db.execute(
                    "UPDATE alerts SET status = ?, assignee = ?, note = ?,"
                    " updated_at = ? WHERE id = ?",
                    (
                        status if status is not None else row["status"],
                        (assignee or None) if assignee is not None
                        else row["assignee"],
                        (note or None) if note is not None else row["note"],
                        now(), alert_id
                    )
                )

                self.db.executemany(
                    "INSERT INTO alert_events (alert_id, time, actor, action,"
                    " detail) VALUES (?,?,?,?,?)",
                    [(alert_id, now(), actor, a, d) for a, d in events]
                )

                self.db.commit()

        return self.get_alert(alert_id)

    def bulk_status(self, ids, status, actor="analyst"):
        """Set a status on many alerts; returns how many changed."""

        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")

        changed = 0

        with self.lock:

            for alert_id in ids:

                row = self.db.execute(
                    "SELECT status FROM alerts WHERE id = ?", (alert_id,)
                ).fetchone()

                if row is None or row["status"] == status:
                    continue

                self.db.execute(
                    "UPDATE alerts SET status = ?, updated_at = ?"
                    " WHERE id = ?",
                    (status, now(), alert_id)
                )

                self.db.execute(
                    "INSERT INTO alert_events (alert_id, time, actor, action,"
                    " detail) VALUES (?,?,?,?,?)",
                    (alert_id, now(), actor, "status",
                     f"{row['status']} -> {status}")
                )

                changed += 1

            self.db.commit()

        return changed

    def clear_source(self, source):
        """Delete every alert and counter of one source (demo data)."""

        with self.lock:
            self.db.execute("DELETE FROM alerts WHERE source = ?", (source,))
            self.db.execute("DELETE FROM traffic WHERE source = ?", (source,))
            self.db.commit()

    def prune_source(self, source, keep):
        """Keep only the newest `keep` untouched alerts of a source."""

        with self.lock:

            self.db.execute(
                "DELETE FROM alerts WHERE source = ? AND status = 'new'"
                " AND id NOT IN (SELECT id FROM alerts WHERE source = ?"
                " ORDER BY id DESC LIMIT ?)",
                (source, source, keep)
            )

            self.db.commit()

    # -- audit trail ---------------------------------------------------------

    def add_audit(self, actor, action, detail=""):

        with self.lock:

            self.db.execute(
                "INSERT INTO audit (time, actor, action, detail) VALUES (?,?,?,?)",
                (now(), actor, action, str(detail)[:500])
            )

            self.db.commit()

    def list_audit(self, limit=200, before_id=None):

        with self.lock:

            rows = self.db.execute(
                "SELECT id, time, actor, action, detail FROM audit"
                + (" WHERE id < ?" if before_id else "")
                + " ORDER BY id DESC LIMIT ?",
                ([before_id] if before_id else []) + [limit]
            ).fetchall()

        return [dict(row) for row in rows]

    def prune_audit(self, keep=50000):

        with self.lock:

            self.db.execute(
                "DELETE FROM audit WHERE id NOT IN"
                " (SELECT id FROM audit ORDER BY id DESC LIMIT ?)",
                (keep,)
            )

            self.db.commit()

    # -- consistent copy for backups ------------------------------------------

    def backup_to(self, path):
        """Write a consistent copy of the whole database (safe while in use)."""

        import sqlite3

        with self.lock:

            target = sqlite3.connect(path)

            try:
                self.db.backup(target)

                # Logins are not part of a backup: restoring one must not
                # bring old session tokens back to life. VACUUM rewrites the
                # file so the deleted rows do not linger in free pages.
                target.execute("DELETE FROM sessions")
                target.commit()
                target.execute("VACUUM")
            finally:
                target.close()

    def restore_from(self, path, keep_session=None):
        """Replace the whole database with a backup, in place (the server keeps running).

        Everyone is signed out afterwards except the session `keep_session` (the administrator who asked),
        and only if that account exists in the backup: a restore after a break-in must not leave old
        sessions alive. A backup from an older version is brought up to date.
        """

        import sqlite3

        with self.lock:

            kept = self.db.execute(
                "SELECT * FROM sessions WHERE token_hash = ?", (keep_session,)
            ).fetchone() if keep_session else None

            source = sqlite3.connect(path)

            try:
                source.backup(self.db)
            finally:
                source.close()

            self.db.execute("DELETE FROM sessions")

            self._migrate()

            if kept is not None and self.db.execute(
                "SELECT 1 FROM users WHERE username = ?", (kept["username"],)
            ).fetchone():
                columns = kept.keys()

                self.db.execute(
                    f"INSERT INTO sessions ({', '.join(columns)}) VALUES ({', '.join('?' * len(columns))})",
                    tuple(kept[c] for c in columns)
                )

            self.db.commit()

    # -- users and sessions ------------------------------------------------

    USER_FIELDS = (
        "password_hash", "role", "disabled", "last_login",
        "totp_secret", "totp_enabled", "totp_step", "recovery"
    )

    def count_users(self):

        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def add_user(self, username, password_hash, role):

        with self.lock:

            self.db.execute(
                "INSERT INTO users (username, password_hash, role, created_at)"
                " VALUES (?,?,?,?)",
                (username, password_hash, role, now())
            )

            self.db.commit()

    def get_user(self, username):

        with self.lock:

            row = self.db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

        return dict(row) if row else None

    def list_users(self):

        with self.lock:

            rows = self.db.execute(
                "SELECT * FROM users ORDER BY username"
            ).fetchall()

        return [dict(row) for row in rows]

    def update_user(self, username, **fields):

        unknown = set(fields) - set(self.USER_FIELDS)

        if unknown:
            raise ValueError(f"cannot update {sorted(unknown)}")

        if not fields:
            return

        with self.lock:

            self.db.execute(
                "UPDATE users SET "
                + ", ".join(f"{name} = ?" for name in fields)
                + " WHERE username = ?",
                [*fields.values(), username]
            )

            self.db.commit()

    def rename_user(self, old, new):
        """Change a username. Sessions are dropped first: they refer to the old name."""

        with self.lock:

            self.db.execute("DELETE FROM sessions WHERE username = ?", (old,))
            self.db.execute("UPDATE users SET username = ? WHERE username = ?", (new, old))
            self.db.execute("UPDATE push_subscriptions SET username = ? WHERE username = ?", (new, old))
            self.db.commit()

    def delete_user(self, username):

        with self.lock:
            self.db.execute("DELETE FROM users WHERE username = ?", (username,))
            self.db.execute("DELETE FROM push_subscriptions WHERE username = ?", (username,))
            self.db.commit()

    def add_session(self, token_hash, username, expires_at, client=None):

        with self.lock:

            # expired sessions are dropped as new ones arrive
            self.db.execute("DELETE FROM sessions WHERE expires_at < ?", (now(),))

            self.db.execute(
                "INSERT INTO sessions (token_hash, username, created_at, expires_at, client)"
                " VALUES (?,?,?,?,?)",
                (token_hash, username, now(), expires_at, client)
            )

            self.db.commit()

    def get_session(self, token_hash):
        """The enabled user a live session belongs to, else None."""

        with self.lock:

            row = self.db.execute(
                "SELECT u.username, u.role FROM sessions s"
                " JOIN users u ON u.username = s.username"
                " WHERE s.token_hash = ? AND s.expires_at >= ? AND u.disabled = 0",
                (token_hash, now())
            ).fetchone()

        return dict(row) if row else None

    def list_sessions(self, username):
        """A person's live sessions, newest first (token hashes are the only identifiers)."""

        with self.lock:

            rows = self.db.execute(
                "SELECT token_hash, created_at, expires_at, client FROM sessions"
                " WHERE username = ? AND expires_at >= ? ORDER BY created_at DESC",
                (username, now())
            ).fetchall()

        return [dict(row) for row in rows]

    def delete_other_sessions(self, username, keep_hash):

        with self.lock:

            done = self.db.execute(
                "DELETE FROM sessions WHERE username = ? AND token_hash != ?", (username, keep_hash)
            ).rowcount

            self.db.commit()

        return done

    def delete_session(self, token_hash):

        with self.lock:
            self.db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            self.db.commit()

    def delete_sessions(self, username):

        with self.lock:
            self.db.execute("DELETE FROM sessions WHERE username = ?", (username,))
            self.db.commit()

    def set_setting(self, key, value):
        """Persist any JSON-serialisable value under a key."""

        with self.lock:

            self.db.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value))
            )

            self.db.commit()

    def get_setting(self, key, default=None):

        with self.lock:

            row = self.db.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()

        return default if row is None else json.loads(row["value"])

    def delete_setting(self, key):

        with self.lock:
            self.db.execute("DELETE FROM settings WHERE key = ?", (key,))
            self.db.commit()

    # -- push subscriptions (browsers that asked for notifications) ------------------------------------

    def add_push(self, endpoint, username, p256dh, auth):
        """Register a browser; the same endpoint registered again takes the new owner and keys."""

        with self.lock:

            self.db.execute(
                "INSERT INTO push_subscriptions (endpoint, username, p256dh, auth, created_at)"
                " VALUES (?,?,?,?,?)"
                " ON CONFLICT(endpoint) DO UPDATE SET username = excluded.username,"
                " p256dh = excluded.p256dh, auth = excluded.auth",
                (endpoint, username, p256dh, auth, now())
            )

            self.db.commit()

    def list_push(self, username=None):

        with self.lock:

            rows = self.db.execute(
                "SELECT endpoint, username, p256dh, auth, created_at FROM push_subscriptions"
                + (" WHERE username = ?" if username is not None else "") + " ORDER BY created_at",
                (username,) if username is not None else ()
            ).fetchall()

        return [dict(row) for row in rows]

    def delete_push(self, endpoint, username=None):

        with self.lock:

            self.db.execute(
                "DELETE FROM push_subscriptions WHERE endpoint = ?"
                + (" AND username = ?" if username is not None else ""),
                (endpoint, username) if username is not None else (endpoint,)
            )

            self.db.commit()

    def log_notification(self, channel, ok, alerts, detail=""):

        with self.lock:

            self.db.execute(
                "INSERT INTO notifications (time, channel, ok, alerts, detail)"
                " VALUES (?,?,?,?,?)",
                (now(), channel, int(ok), alerts, detail[:500])
            )

            self.db.commit()

    # -- reads -----------------------------------------------------------

    @staticmethod
    def _where(status=None, risk=None, attack_type=None, source=None,
               q=None, before_id=None):

        clauses, params = [], []

        if status == "open":
            clauses.append("status IN ('new', 'investigating')")
        elif status and status != "all":
            clauses.append("status = ?")
            params.append(status)

        for column, value in (
            ("risk", risk), ("attack_type", attack_type), ("source", source)
        ):
            if value and value != "all":
                clauses.append(f"{column} = ?")
                params.append(value)

        if q:
            clauses.append(
                "(CAST(id AS TEXT) = ? OR src_ip LIKE ? OR dst_ip LIKE ?"
                " OR note LIKE ? OR assignee LIKE ?)"
            )
            like = f"%{q}%"
            params += [q.lstrip("#"), like, like, like, like]

        if before_id:
            clauses.append("id < ?")
            params.append(before_id)

        return (
            " WHERE " + " AND ".join(clauses) if clauses else "",
            params
        )

    def list_alerts(self, limit=100, **filters):

        where, params = self._where(**filters)

        with self.lock:

            rows = self.db.execute(
                f"SELECT {LIST_COLUMNS} FROM alerts{where}"
                " ORDER BY id DESC LIMIT ?",
                params + [limit]
            ).fetchall()

        return [dict(row) for row in rows]

    def get_alert(self, alert_id):

        with self.lock:

            row = self.db.execute(
                "SELECT * FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()

            if row is None:
                return None

            events = self.db.execute(
                "SELECT time, actor, action, detail FROM alert_events"
                " WHERE alert_id = ? ORDER BY id",
                (alert_id,)
            ).fetchall()

        alert = dict(row)

        alert["posterior"] = json.loads(alert["posterior"] or "null")
        alert["features"] = json.loads(alert["features"] or "null")
        alert["events"] = [dict(e) for e in events]

        return alert

    def stats(self, source=None):

        where, params = self._where(source=source)

        with self.lock:

            def grouped(column):

                rows = self.db.execute(
                    f"SELECT {column} AS k, COUNT(*) AS n FROM alerts{where}"
                    f" GROUP BY {column}",
                    params
                ).fetchall()

                return {row["k"]: row["n"] for row in rows}

            by_type = grouped("attack_type")
            by_risk = grouped("risk")
            by_status = grouped("status")

            # attack type x risk band, for the overview's threat matrix
            matrix = {}

            for row in self.db.execute(
                f"SELECT attack_type AS t, risk AS r, COUNT(*) AS n FROM alerts{where}"
                " GROUP BY attack_type, risk",
                params
            ).fetchall():
                matrix.setdefault(row["t"], {})[row["r"]] = row["n"]

            traffic_where = (
                " WHERE source = ?" if source and source != "all" else ""
            )

            flows = self.db.execute(
                "SELECT COALESCE(SUM(flows), 0) FROM traffic"
                + traffic_where,
                [source] if traffic_where else []
            ).fetchone()[0]

        return {
            "total": flows,
            "alerts": sum(by_type.values()),
            "by_type": by_type,
            "by_risk": by_risk,
            "by_status": by_status,
            "by_type_risk": matrix
        }

    def sources(self):

        with self.lock:

            rows = self.db.execute(
                "SELECT DISTINCT source FROM traffic"
            ).fetchall()

        return sorted(r["source"] for r in rows)

    def recent_notifications(self, limit=10):

        with self.lock:

            rows = self.db.execute(
                "SELECT time, channel, ok, alerts, detail FROM notifications"
                " ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()

        return [dict(r) for r in rows]

    def close(self):

        with self.lock:
            self.db.close()
