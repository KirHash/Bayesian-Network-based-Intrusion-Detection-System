"""Shared state and logic behind the routes: the live hub, scoring and ingest, the background loops, who may do what, and security events. api.py builds the app from these and the routes."""
import asyncio
import glob
import hashlib
import hmac
import json
import logging
import os
import re
import sys
import time
from collections import Counter, deque
from datetime import datetime
from pathlib import Path
import numpy as np
from collections import namedtuple
from fastapi import HTTPException
import lifecycle
from autostart import Autostart
from data_loader import dataset_glob, load_all, train_val_test_split
from detector import Detector
from drift import DriftMonitor
from feature_extractor import ALIASES
from throttle import Throttle


MAX_TIMELINE = 120

# points kept per source for the drift history, and the least time between two of them
DRIFT_POINTS = 360
DRIFT_EVERY_SECONDS = 10


MAX_RECENT = 500


# Newest flows of each batch kept for the "recent flows" view
RECENT_PER_BATCH = 100


MAX_REPLAY_RATE = 2000


MAX_FLOWS_PER_REQUEST = 5000


REPLAY_ALERTS_KEPT = 20000


SOURCES = ("capture", "api", "replay")


# Raw flow fields stored with an alert for the detail view
INSPECT = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Average Packet Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Fwd IAT Min"
]


FRONTEND = Path(__file__).parent / "frontend" / "dist"


# Read per request, so they can change without re-importing (and in tests)
def admin_token():
    return os.environ.get("IDS_ADMIN_TOKEN")


def env_api_key():
    return os.environ.get("IDS_API_KEY")


def data_dir():
    return os.environ.get("IDS_DATA_DIR", "captures")


def demo_data_glob():
    """CIC-IDS-2017 CSVs the demo replays and the model trains on."""

    return dataset_glob()


def digest_key(key):
    return hashlib.sha256(key.encode()).hexdigest()


class Hub:
    """Live state: the model, websocket clients and per-source monitors."""

    def __init__(self):

        self.detector = None

        # one-time tickets that let a browser open the live feed without putting its session token in a URL
        self.tickets = {}

        # repeated bad bearer tokens / API keys from one address
        self.token_guesses = Throttle(limit=30, window=300)
        self.key_guesses = Throttle(limit=30, window=300)

        # every sign-in request from one address, right or wrong: a script cannot try passwords faster than this
        self.login_rate = Throttle(limit=30, window=60)

        self.store = None
        self.notifier = None
        self.capture = None
        self.accounts = None
        self.backups = None
        self.push = None
        self.jobs = None
        self.proxy = None
        self.secrets = None
        self.autostart = Autostart()
        self.logs = None

        self.replay_pool = None
        self.replay_order = None
        self.started = time.time()
        self.replay_pos = 0
        self.replay = {"running": False, "rate": 50}

        self.clients = set()
        self.lock = asyncio.Lock()
        self.demo_lock = asyncio.Lock()

        # Every recent flow, benign ones included (alerts alone would hide
        # a working capture whose traffic is all normal)
        self.recent = deque(maxlen=MAX_RECENT)
        self.last_seen = {}

        # Per-second ticks for the timeline, then per-source monitors
        self.ticks = deque(maxlen=MAX_TIMELINE * len(SOURCES))
        self.confusion = {s: Counter() for s in SOURCES}
        self.drift = {}

        # how drift moved over time, one point every few seconds per source (see record_drift)
        self.drift_history = {s: deque(maxlen=DRIFT_POINTS) for s in SOURCES}

    def reset_live(self, source):
        """Forget one source's timeline, accuracy counters and drift."""

        self.confusion[source] = Counter()
        self.drift.pop(source, None)
        self.drift_history[source].clear()
        self.last_seen.pop(source, None)

        keep = [f for f in self.recent if f["source"] != source]

        self.recent.clear()
        self.recent.extend(keep)

        kept = [t for t in self.ticks if t["source"] != source]

        self.ticks.clear()
        self.ticks.extend(kept)

    def drift_monitor(self, source):

        if source not in self.drift:
            self.drift[source] = DriftMonitor(self.detector)

        return self.drift[source]

    def accuracy(self, source=None):
        """Precision / recall measured on flows with a known ground truth."""

        total = Counter()

        for s, counts in self.confusion.items():
            if source in (None, "all", s):
                total.update(counts)

        tp, fp, fn, tn = (total[k] for k in ("tp", "fp", "fn", "tn"))

        def ratio(a, b):
            return round(a / b, 4) if b else None

        return {
            "labelled": tp + fp + fn + tn,
            "precision": ratio(tp, tp + fp),
            "recall": ratio(tp, tp + fn),
            "false_alarm_rate": ratio(fp, fp + tn)
        }

    async def broadcast(self, message):

        text = json.dumps(message)

        for client in list(self.clients):
            try:
                await client.send_text(text)
            except Exception:
                self.clients.discard(client)


hub = Hub()


def record_drift(source, report, now=None):
    """Add a point to a source's drift history unless one was added a moment ago. Returns whether it did."""

    history = hub.drift_history[source]

    now = time.time() if now is None else now

    if history and now - history[-1]["at"] < DRIFT_EVERY_SECONDS:
        return False

    history.append({
        "at": now,
        "t": datetime.fromtimestamp(now).strftime("%H:%M:%S"),
        "status": report.get("status"),
        "max_psi": report.get("max_psi"),
        "anomaly_rate": report.get("anomaly_rate")
    })

    return True


def address(flow, column):
    """A flow's source or destination address, or None when it has none.

    Some datasets (CSE-CIC-IDS2018's) carry no addresses, so a pool mixing files has gaps."""

    value = flow.get(column)

    if value is None or (isinstance(value, float) and np.isnan(value)):
        return None

    text = str(value).strip()

    return None if text in ("", "nan", "None") else text


def score_batch(flows, labels, source):
    """
    Blocking: score a batch. Returns (result, alert records without ids,
    recent-flow rows). Only flagged flows become alerts; benign flows are
    counted and kept briefly in the recent-flows view.
    """

    if hub.detector is None:
        raise RuntimeError(NO_MODEL)

    result = hub.detector.score(flows, details=True)

    when = datetime.now().isoformat(timespec="seconds")

    records = []

    # The newest flows of the batch, flagged or not, for the live view
    recent = {}

    for i in range(max(0, len(result) - RECENT_PER_BATCH), len(result)):

        flow, row = flows.iloc[i], result.iloc[i]

        recent[i] = {
            "time": when,
            "source": source,
            "prediction": row["prediction"],
            "attack_type": row["attack_type"],
            "risk": row["risk"],
            "probability": round(float(row["probability"]) * 100, 2),
            "label": None if labels is None else labels[i],
            "src_ip": address(flow, "Source IP"),
            "dst_ip": address(flow, "Destination IP"),
            "dst_port": int(float(flow["Destination Port"])),
            "alert_id": None
        }

    for i in np.flatnonzero((result["prediction"] == "ATTACK").values):

        flow = flows.iloc[i]

        row = result.iloc[i]

        records.append({
            "time": when,
            "source": source,
            "attack_type": row["attack_type"],
            "reason": row["reason"],
            "risk": row["risk"],
            "probability": round(float(row["probability"]) * 100, 2),
            "surprise": round(float(row["surprise"]), 1),
            "label": None if labels is None else labels[i],
            "src_ip": address(flow, "Source IP"),
            "dst_ip": address(flow, "Destination IP"),
            "dst_port": int(float(flow["Destination Port"])),
            "posterior": row["posterior"],
            # the forest's second opinion (percent), absent for models without one
            "forest": (
                None if np.isnan(row["forest"]) else round(float(row["forest"]) * 100, 2)
            ),
            "features": {
                name: float(flow[name])
                for name in INSPECT
                if name in flows.columns
            }
        })

        if i in recent:
            recent[i]["_record"] = len(records) - 1

    return result, records, list(recent.values())


def public(alert):
    """List-view fields of an alert (no posterior / feature detail)."""

    return {
        k: v for k, v in alert.items()
        if k not in ("posterior", "features", "events")
    }


async def ingest(flows, labels=None, source="api"):

    # Accept padded names and newer CICFlowMeter spellings
    flows = flows.rename(columns=lambda c: ALIASES.get(c.strip(), c.strip()))

    async with hub.lock:

        result, records, recent = await asyncio.to_thread(
            score_batch, flows, labels, source
        )

        ids = await asyncio.to_thread(hub.store.add_alerts, records)

        for alert_id, record in zip(ids, records):
            record["id"] = alert_id
            record["status"] = "new"

        for row in recent:

            k = row.pop("_record", None)

            row["alert_id"] = None if k is None else records[k]["id"]

        hub.recent.extend(recent)

        hub.last_seen[source] = datetime.now()

        await asyncio.to_thread(
            hub.store.add_traffic, source, len(result), len(records)
        )

        if labels is not None:

            actual = np.array(labels) != "BENIGN"

            flagged = (result["prediction"] == "ATTACK").values

            counts = hub.confusion[source]

            counts["tp"] += int((actual & flagged).sum())
            counts["fp"] += int((~actual & flagged).sum())
            counts["fn"] += int((actual & ~flagged).sum())
            counts["tn"] += int((~actual & ~flagged).sum())

        monitor = hub.drift_monitor(source)

        monitor.update(flows, result)

        record_drift(source, monitor.report())

        hub.notifier.submit(records)

        tick = {
            "source": source,
            "t": datetime.now().strftime("%H:%M:%S"),
            "flows": len(result),
            "alerts": len(records)
        }

        hub.ticks.append(tick)

    await hub.broadcast({
        "type": "batch",
        "source": source,
        "tick": tick,
        "alerts": [public(r) for r in records[-100:]],
        "drift": monitor.report()
    })

    return result, records


async def replay_loop():

    while True:

        await asyncio.sleep(1)

        if not hub.replay["running"] or hub.replay_pool is None:
            continue

        order = hub.replay_order

        ids = [
            order[(hub.replay_pos + k) % len(order)]
            for k in range(hub.replay["rate"])
        ]

        hub.replay_pos = (hub.replay_pos + len(ids)) % len(order)

        batch = hub.replay_pool.iloc[ids]

        await ingest(
            batch.drop(columns="Label").reset_index(drop=True),
            labels=batch["Label"].tolist(),
            source="replay"
        )


async def prune_loop():

    while True:

        await asyncio.sleep(60)

        await asyncio.to_thread(
            hub.store.prune_source, "replay", REPLAY_ALERTS_KEPT
        )


log = logging.getLogger("ids")


def security_event(kind, text):
    """Something an admin should know about: kept in the audit trail and sent to the notification channels."""

    if hub.store:
        hub.store.add_audit("-", f"security: {kind}", text)

    log.warning("security: %s: %s", kind, text)

    if hub.notifier:
        hub.notifier.security(kind, text)


def forest_confirm_setting():
    """Whether classifier alerts need the forest's agreement (on unless an admin turned it off)."""

    return bool(hub.store.get_setting("forest_confirm", True)) if hub.store else True


def reload_model():
    """Load the model file now on disk; a bad file leaves the old one running."""

    detector = Detector(use_forest=forest_confirm_setting())

    hub.detector = detector

    # drift references belong to the model they were built from
    hub.drift.clear()

    log.info("model reloaded (trained %s)",
             detector.bundle.get("card", {}).get("trained_at", "unknown"))


def dashboard_upstream():
    """host:port this dashboard listens on, as the proxy should reach it."""

    command = lifecycle.original_command()

    def option(flag, default):

        for i, part in enumerate(command[:-1]):
            if part == flag:
                return command[i + 1]

        return default

    host = option("--host", "127.0.0.1")

    return f"{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{option('--port', '8000')}"


def launcher_command():
    """The command that starts the whole online setup, when go_online.py started this server.

    Starting only the server at login would leave the site without its tunnel."""

    if os.environ.get("IDS_LAUNCHER") != "go_online":
        return None

    return [sys.executable, str(Path(__file__).parent / "go_online.py"), "--no-browser"]


def started_behind_proxy():

    return "--behind-proxy" in lifecycle.original_command()


NO_MODEL = (
    "no model has been trained yet: open Operations, add training data and press Retrain"
)


def require_model():

    if hub.detector is None:
        raise HTTPException(503, NO_MODEL)


DEMO_PER_LABEL = 15_000


def demo_cache_path():
    """Beside the database, so a container keeps it in its data volume."""

    return Path(os.path.abspath(os.environ.get("IDS_DB", "ids.db"))).with_name("demo_pool.pkl")


def demo_pool(pattern):
    """The held-out flows the demo replays: up to 15,000 per label, remembered on disk.

    Reading and splitting every CSV (gigabytes) takes minutes, so it is done once per set of files and the
    small result is kept; it is made again when a file is added, removed or changed.
    """

    import pandas as pd

    files = sorted(glob.glob(pattern))

    stamp = hashlib.sha256(
        "|".join(f"{os.path.basename(f)}:{os.path.getsize(f)}:{int(os.path.getmtime(f))}" for f in files).encode()
    ).hexdigest()

    cache = demo_cache_path()

    try:
        saved = pd.read_pickle(cache)

        if saved.get("stamp") == stamp:
            return saved["pool"]
    except Exception:
        pass

    pool = train_val_test_split(load_all(pattern))[2]

    column = next((c for c in ("Label", "label") if c in pool.columns), None)

    if column:
        pool = pd.concat(
            [part.sample(min(len(part), DEMO_PER_LABEL), random_state=0) for _, part in pool.groupby(column)]
        )

    pool = pool.sample(frac=1, random_state=0).reset_index(drop=True)

    try:
        pd.to_pickle({"stamp": stamp, "pool": pool}, cache)
    except OSError as error:
        log.warning("could not keep the demo flows (%s); the next start will rebuild them", error)

    return pool


async def load_demo():
    """Load the held-out dataset flows used by the demo, once, on demand."""

    async with hub.demo_lock:

        if hub.replay_pool is not None:
            return

        if not glob.glob(demo_data_glob()):
            raise FileNotFoundError(
                f"demo data not found ({demo_data_glob()}); the demo replays "
                "CIC-IDS-2017 CSVs, which are not needed for real traffic"
            )

        def load():
            return demo_pool(demo_data_glob())

        pool = await asyncio.to_thread(load)

        # files without addresses leave gaps; empty strings keep the pool JSON-safe
        for column in ("Source IP", "Destination IP"):
            if column in pool.columns:
                pool[column] = pool[column].fillna("")

        hub.replay_order = np.random.default_rng(0).permutation(len(pool))

        hub.replay_pool = pool


Principal = namedtuple("Principal", "name role via")


OPEN = Principal("local", "admin", "open")


PUBLIC = {
    ("POST", "/api/score"),       # flow exporters use an API key
    ("GET", "/api/auth"),
    ("POST", "/api/login"),
    ("POST", "/api/signup"),
    ("GET", "/api/healthz"),
    ("HEAD", "/api/healthz")      # uptime monitors often ask with HEAD
}


def auth_required():

    return bool(admin_token()) or hub.accounts.any_users()


def principal_for(token):
    """Who a bearer token belongs to, or None."""

    if not auth_required():
        return OPEN

    expected = admin_token()

    if expected and token and hmac.compare_digest(token, expected):
        return Principal("admin-token", "admin", "token")

    user = hub.accounts.resolve(token)

    return Principal(user["username"], user["role"], "session") if user else None


# Admin-only whatever the method: these expose or change how the server runs
ADMIN_AREAS = (
    "/api/users", "/api/capture/options", "/api/logs", "/api/audit",
    "/api/server", "/api/files", "/api/jobs", "/api/backup", "/api/proxy",
    "/api/notifications/config", "/api/signup-policy"
)


# Changes worth an audit line (alert handling is already in each alert's history)
UNAUDITED = ("/api/alerts", "/api/score", "/api/login", "/api/logout", "/api/signup")


def required_role(method, path):
    """The lowest role allowed to make this request."""

    if path.startswith(ADMIN_AREAS):
        return "admin"

    if method in ("GET", "HEAD", "OPTIONS"):
        return "viewer"

    if path in ("/api/logout", "/api/ws-ticket") or path.startswith(("/api/account", "/api/push")):
        return "viewer"

    if path == "/api/alerts/bulk" or (
        method == "PATCH" and path.startswith("/api/alerts/")
    ):
        return "analyst"

    return "admin"


def bearer(request):

    return request.headers.get("authorization", "").removeprefix("Bearer ")


CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    # React sets style attributes on elements
    "style-src 'self' 'unsafe-inline'",
    "connect-src 'self' ws: wss:",
    "img-src 'self' data:",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'"
])


def cors_origins():
    """Sites allowed to call this API from a browser (IDS_CORS_ORIGINS, comma separated).

    Only needed when the dashboard's pages are hosted elsewhere, e.g. on Netlify.
    Sign-in uses a bearer token, not cookies, so no site gains ambient authority.
    A bare "*" is refused: every listed origin must be spelled out.
    """

    origins = []

    for item in os.environ.get("IDS_CORS_ORIGINS", "").split(","):

        item = item.strip().rstrip("/")

        if not item:
            continue

        if not re.fullmatch(r"https?://[A-Za-z0-9.-]+(:\d{1,5})?", item):
            log.warning("IDS_CORS_ORIGINS: ignoring %r (expected https://host[:port])", item)
            continue

        origins.append(item)

    return origins


TICKET_SECONDS = 30


def redeem_ticket(ticket):
    """Who a ticket was issued to, spending it; None when unknown, used or expired."""

    entry = hub.tickets.pop(ticket or "", None)

    return entry[0] if entry and entry[1] >= time.time() else None
