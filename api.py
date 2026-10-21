"""
FastAPI backend for the React dashboard.

    uvicorn api:app --port 8000

Scores flows with the Bayesian network, stores alerts in SQLite (ids.db),
tracks drift and sends notifications, and pushes every scored batch to
connected browsers over /ws. Flows arrive from three sources:

    capture  flows from capture.py (real traffic) or any CICFlowMeter CSV
    api      anything posted to /api/score
    replay   held-out dataset flows replayed for demos

Environment: IDS_DB (database path), IDS_API_KEY (if set, /api/score needs
a matching X-API-Key header; a key can also be created in the dashboard),
IDS_ADMIN_TOKEN (a shared admin credential; accounts are the normal way
in), IDS_DEMO_DATA (CIC-IDS-2017 CSVs for the optional demo), IDS_DATA_DIR
(folder of pcap / CSV files the dashboard may open, default ./captures),
IDS_NOTIFY_CONFIG (notification settings).
"""
import asyncio
import glob
import hashlib
import hmac
import json
import logging
import os
import pickle
import platform
import re
import secrets
import sys
import tempfile
import time
from collections import Counter, deque
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from collections import namedtuple

from fastapi import (
    Request,
    FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.background import BackgroundTask
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import files
import lifecycle
import logbuffer
from accounts import RANK, AccountError, Accounts, Locked
from autostart import Autostart
from bayesian_engine import model_path
from jobs import KINDS, JobBusy, JobManager
from secrets_store import SecretBox
from capture_manager import CaptureManager, list_files, list_interfaces
from data_loader import dataset_glob, load_all, train_val_test_split
from detector import Detector
from drift import DriftMonitor
from feature_extractor import ALIASES
from notifier import Notifier, SettingsError
from platform_check import diagnose
from proxy_manager import ProxyError, ProxyManager
from storage import Store

MAX_TIMELINE = 120
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
        self.store = None
        self.notifier = None
        self.capture = None
        self.accounts = None
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

    def reset_live(self, source):
        """Forget one source's timeline, accuracy counters and drift."""

        self.confusion[source] = Counter()
        self.drift.pop(source, None)
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
            "src_ip": str(flow["Source IP"]) if "Source IP" in flows else None,
            "dst_ip": (
                str(flow["Destination IP"]) if "Destination IP" in flows else None
            ),
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
            "src_ip": str(flow["Source IP"]) if "Source IP" in flows else None,
            "dst_ip": (
                str(flow["Destination IP"])
                if "Destination IP" in flows else None
            ),
            "dst_port": int(float(flow["Destination Port"])),
            "posterior": row["posterior"],
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


def reload_model():
    """Load the model file now on disk; a bad file leaves the old one running."""

    detector = Detector()

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


def started_behind_proxy():

    return "--behind-proxy" in lifecycle.original_command()


NO_MODEL = (
    "no model has been trained yet: open Operations, add training data and press Retrain"
)


def require_model():

    if hub.detector is None:
        raise HTTPException(503, NO_MODEL)


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
            return train_val_test_split(load_all(demo_data_glob()))[2]

        pool = await asyncio.to_thread(load)

        hub.replay_order = np.random.default_rng(0).permutation(len(pool))

        hub.replay_pool = pool


@asynccontextmanager
async def lifespan(app):

    hub.logs = logbuffer.install()

    try:
        hub.detector = await asyncio.to_thread(Detector)
    except (OSError, pickle.UnpicklingError, EOFError, KeyError) as error:
        # A fresh install has no model yet: the dashboard still starts, so the
        # model can be trained from Operations
        hub.detector = None
        log.warning("no usable model at %s (%s); train one from Operations", model_path(), error)

    db_path = os.environ.get("IDS_DB", "ids.db")

    hub.store = Store(db_path)

    hub.secrets = SecretBox(db_path + ".key")

    await asyncio.to_thread(hub.store.prune_audit)

    log.info("server started (%s)", (
        "model trained " + hub.detector.bundle.get("card", {}).get("trained_at", "unknown")
        if hub.detector else "no model yet"
    ))

    hub.accounts = Accounts(hub.store)

    hub.notifier = Notifier(hub.store, box=hub.secrets)
    hub.notifier.start()

    loop = asyncio.get_running_loop()

    def push(message):
        """Broadcast from any thread."""

        asyncio.run_coroutine_threadsafe(hub.broadcast(message), loop)

    def job_changed(job):

        log.info("job %s (%s): %s", job.id, job.kind, job.state)

        push({"type": "job", "job": job.summary()})

    def job_succeeded(job):

        if KINDS[job.kind]["reloads_model"]:

            reload_model()

            hub.store.add_audit(job.actor, "model reloaded", f"after job {job.id}")

            push({"type": "model_changed"})

    hub.proxy = ProxyManager(
        hub.store, dashboard_upstream,
        lambda: files.max_bytes() // (1024 * 1024) + 1,
        auth_required,
        cert_dir=str(files.area_dir("certs", data_dir()))
    )

    hub.proxy.adopt_existing()

    settings = hub.proxy.settings()

    if settings["autostart"]:
        try:
            await asyncio.to_thread(hub.proxy.start)
            log.info("proxy started (%s) at %s", settings["engine"], hub.proxy.url())
        except ProxyError as error:
            log.warning("proxy did not start with the server: %s", error)

    hub.jobs = JobManager(
        os.path.dirname(os.path.abspath(__file__)),
        on_change=job_changed, on_success=job_succeeded
    )

    def push_capture_status(status):
        """Called from capture threads; hands the update to the event loop."""

        asyncio.run_coroutine_threadsafe(
            hub.broadcast({"type": "capture", "capture": status}), loop
        )

    hub.capture = CaptureManager(
        ingest, loop, hub.store, data_dir=data_dir(),
        on_status=push_capture_status
    )

    hub.capture.autostart()

    tasks = [
        asyncio.create_task(replay_loop()),
        asyncio.create_task(prune_loop())
    ]

    yield

    for task in tasks:
        task.cancel()

    await asyncio.to_thread(hub.capture.stop)

    log.info("server stopping")

    hub.notifier.stop()

    hub.store.close()


app = FastAPI(title="Bayesian IDS", lifespan=lifespan)


# -- who is asking -----------------------------------------------------------
#
# Three situations, checked on every request:
#   no accounts and no IDS_ADMIN_TOKEN   open: every request is an admin
#                                        (a local, single-user setup)
#   IDS_ADMIN_TOKEN set                  the token counts as an admin
#   accounts exist                       sign in; the session token is a bearer

Principal = namedtuple("Principal", "name role via")

OPEN = Principal("local", "admin", "open")

PUBLIC = {
    ("POST", "/api/score"),       # flow exporters use an API key
    ("GET", "/api/auth"),
    ("POST", "/api/login"),
    ("GET", "/api/healthz")
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
    "/api/notifications/config"
)

# Changes worth an audit line (alert handling is already in each alert's history)
UNAUDITED = ("/api/alerts", "/api/score", "/api/login", "/api/logout")


def required_role(method, path):
    """The lowest role allowed to make this request."""

    if path.startswith(ADMIN_AREAS):
        return "admin"

    if method in ("GET", "HEAD", "OPTIONS"):
        return "viewer"

    if path == "/api/logout":
        return "viewer"

    if path == "/api/alerts/bulk" or (
        method == "PATCH" and path.startswith("/api/alerts/")
    ):
        return "analyst"

    return "admin"


def bearer(request):

    return request.headers.get("authorization", "").removeprefix("Bearer ")


@app.middleware("http")
async def check_access(request, call_next):

    path = request.url.path

    if not path.startswith("/api/") or (request.method, path) in PUBLIC:
        return await call_next(request)

    who = await asyncio.to_thread(principal_for, bearer(request))

    if who is None:
        return JSONResponse({"detail": "sign in required"}, status_code=401)

    needed = required_role(request.method, path)

    if RANK[who.role] < RANK[needed]:

        await asyncio.to_thread(
            hub.store.add_audit, who.name, f"denied {request.method} {path}",
            f"needs {needed}, has {who.role}"
        )

        return JSONResponse(
            {"detail": f"this needs the {needed} role"}, status_code=403
        )

    request.state.who = who

    request.state.audit = ""

    response = await call_next(request)

    if request.method not in ("GET", "HEAD", "OPTIONS") and not path.startswith(UNAUDITED):

        name = "local" if who.via == "open" else who.name

        await asyncio.to_thread(
            hub.store.add_audit, name, f"{request.method} {path}",
            f"{response.status_code} {request.state.audit}".strip()
        )

    return response


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


@app.middleware("http")
async def security_headers(request, call_next):
    """Headers that make a browser refuse framing, sniffing and foreign scripts."""

    response = await call_next(request)

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)

    secure = (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto") == "https"
    )

    if secure:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000"
        )

    return response


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


if cors_origins():

    # added last, so it is outermost and answers preflight requests before sign-in is asked
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins(),
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600
    )


def actor(request, fallback="analyst"):
    """Name recorded in the alert history for a change."""

    who = getattr(request.state, "who", OPEN)

    return fallback if who.via == "open" else who.name


@app.get("/api/healthz")
async def healthz():
    """For load balancers and service monitors: no login needed."""

    try:
        await asyncio.to_thread(hub.store.get_setting, "health_probe")
        database = True
    except Exception:
        database = False

    healthy = hub.detector is not None and database

    return JSONResponse(
        {
            "status": "ok" if healthy else "degraded",
            "model": hub.detector is not None,
            "database": database,
            "capture": hub.capture.status()["state"] if hub.capture else None,
            "uptime_seconds": round(time.time() - hub.started)
        },
        status_code=200 if healthy else 503
    )


@app.get("/api/auth")
async def auth_status(request: Request):
    """What the sign-in page needs to know, answerable without signing in."""

    who = await asyncio.to_thread(principal_for, bearer(request))

    return {
        "required": await asyncio.to_thread(auth_required),
        "ok": who is not None,
        "user": who.name if who else None,
        "role": who.role if who else None,
        "methods": {
            "password": await asyncio.to_thread(hub.accounts.any_users),
            "token": bool(admin_token())
        }
    }


class Login(BaseModel):

    username: str
    password: str


@app.post("/api/login")
async def login(credentials: Login, request: Request):

    client = request.client.host if request.client else "?"

    try:
        token, user = await asyncio.to_thread(
            hub.accounts.login, credentials.username, credentials.password,
            client
        )
    except Locked as error:

        await asyncio.to_thread(
            hub.store.add_audit, "-", "login locked",
            f"{credentials.username} from {client}"
        )

        return JSONResponse(
            {"detail": str(error)}, status_code=429,
            headers={"Retry-After": str(error.retry_after)}
        )
    except AccountError as error:

        await asyncio.to_thread(
            hub.store.add_audit, "-", "login failed",
            f"{credentials.username} from {client}"
        )

        raise HTTPException(401, str(error))

    await asyncio.to_thread(hub.store.add_audit, user["username"], "login", client)

    return {
        "token": token,
        "username": user["username"],
        "role": user["role"],
        "expires_at": user["expires_at"]
    }


@app.post("/api/logout")
async def logout(request: Request):

    await asyncio.to_thread(hub.accounts.logout, bearer(request))

    return {"ok": True}


# -- user management (admins) ------------------------------------------------

class NewUser(BaseModel):

    username: str
    password: str
    role: str = "viewer"


class UserChange(BaseModel):

    role: str | None = None
    password: str | None = None
    disabled: bool | None = None


def account_call(function, *args):
    """Run an account change; mistakes become 400s."""

    try:
        return function(*args)
    except AccountError as error:
        raise HTTPException(400, str(error))


@app.get("/api/users")
async def list_users():

    return await asyncio.to_thread(hub.accounts.users)


@app.post("/api/users")
async def create_user(user: NewUser, request: Request):

    request.state.audit = f"{user.username} ({user.role})"

    name = await asyncio.to_thread(
        account_call, hub.accounts.create, user.username, user.password, user.role
    )

    return {"username": name, "role": user.role}


@app.patch("/api/users/{username}")
async def change_user(username: str, change: UserChange, request: Request):

    me = request.state.who

    request.state.audit = username + (
        f" role={change.role}" if change.role else ""
    ) + (" password reset" if change.password else "") + (
        f" disabled={change.disabled}" if change.disabled is not None else ""
    )

    if change.disabled and username.lower() == me.name:
        raise HTTPException(409, "you cannot disable your own account")

    def apply():

        if change.role is not None:
            hub.accounts.set_role(username, change.role)

        if change.password is not None:
            hub.accounts.set_password(username, change.password)

        if change.disabled is not None:
            hub.accounts.set_disabled(username, change.disabled)

    await asyncio.to_thread(account_call, apply)

    return {"ok": True}


@app.delete("/api/users/{username}")
async def delete_user(username: str, request: Request):

    request.state.audit = username

    if username.lower() == request.state.who.name:
        raise HTTPException(409, "you cannot delete your own account")

    await asyncio.to_thread(account_call, hub.accounts.delete, username)

    return {"ok": True}


# -- model and monitoring -------------------------------------------------

@app.get("/api/model")
def model_info():

    if hub.detector is None:
        return {
            "trained": False, "threshold": None, "classes": [], "features": 0,
            "feature_edges": 0, "card": {}, "message": NO_MODEL,
            "previous_available": os.path.exists(model_path() + ".previous"),
            "dataset_files": len(glob.glob(dataset_glob()))
        }

    bundle = hub.detector.bundle

    model = bundle["model"]

    return {
        "trained": True,
        "threshold": hub.detector.threshold,
        "classes": list(
            model.get_cpds("AttackType").state_names["AttackType"]
        ),
        "features": len(model.nodes()) - 1,
        "feature_edges": sum(
            1 for edge in model.edges() if edge[0] != "AttackType"
        ),
        "card": bundle.get("card", {}),
        "previous_available": os.path.exists(model_path() + ".previous"),
        "dataset_files": len(glob.glob(dataset_glob()))
    }


@app.post("/api/model/reload")
async def model_reload(request: Request):
    """Load bayesian_ids.pkl again, e.g. after replacing the file by hand."""

    try:
        await asyncio.to_thread(reload_model)
    except Exception as error:
        raise HTTPException(400, f"could not load the model file: {error}")

    await hub.broadcast({"type": "model_changed"})

    return model_info()


@app.post("/api/model/rollback")
async def model_rollback(request: Request):
    """Go back to the model that was in use before the last retraining."""

    path = model_path()

    previous = path + ".previous"

    if not os.path.exists(previous):
        raise HTTPException(400, "there is no previous model to go back to")

    def swap_files():

        keep = path + ".rollback"

        os.replace(path, keep)
        os.replace(previous, path)
        os.replace(keep, previous)

        reload_model()

    try:
        await asyncio.to_thread(swap_files)
    except Exception as error:
        raise HTTPException(500, f"rollback failed: {error}")

    request.state.audit = "swapped with the previous model"

    await hub.broadcast({"type": "model_changed"})

    return model_info()


# -- retraining and other maintenance jobs ----------------------------------------------

class JobStart(BaseModel):

    kind: str


@app.get("/api/jobs")
def list_jobs():

    return {"jobs": hub.jobs.recent(), "kinds": {
        k: {"title": v["title"], "needs_dataset": v["needs_dataset"]}
        for k, v in KINDS.items()
    }}


@app.post("/api/jobs")
async def start_job(job: JobStart, request: Request):

    if job.kind not in KINDS:
        raise HTTPException(400, f"unknown job; choose from {sorted(KINDS)}")

    if KINDS[job.kind]["needs_dataset"] and not glob.glob(dataset_glob()):
        raise HTTPException(
            400,
            f"no dataset found ({dataset_glob()}). Upload CIC-IDS-2017 CSVs "
            "in the Data section first."
        )

    who = request.state.who

    try:
        started = await asyncio.to_thread(
            hub.jobs.start, job.kind, "local" if who.via == "open" else who.name
        )
    except JobBusy as error:
        raise HTTPException(409, str(error))

    request.state.audit = f"{job.kind} (job {started.id})"

    return started.summary()


@app.get("/api/jobs/{job_id}")
def job_output(job_id: int, after: int = 0):

    found = hub.jobs.get(job_id)

    if found is None:
        raise HTTPException(404, "no such job")

    return found.tail(after)


@app.post("/api/jobs/{job_id}/cancel")
async def cancel_job(job_id: int, request: Request):

    if not await asyncio.to_thread(hub.jobs.cancel, job_id):
        raise HTTPException(409, "that job is not running")

    request.state.audit = f"job {job_id}"

    return {"ok": True}


@app.get("/api/stats")
async def get_stats(source: str = "all"):

    stats = await asyncio.to_thread(hub.store.stats, source)

    return {
        **stats,
        **hub.accuracy(source),
        "replay": hub.replay
    }


@app.get("/api/drift")
def get_drift(source: str = "all"):

    wanted = [s for s in SOURCES if source in ("all", s)]

    return {s: hub.drift_monitor(s).report() for s in wanted if s in hub.drift}


@app.get("/api/flows")
def recent_flows(
    source: str = "all",
    verdict: str = "all",
    limit: int = Query(100, ge=1, le=MAX_RECENT)
):
    """The newest scored flows, benign ones included (kept in memory)."""

    rows = (
        f for f in reversed(hub.recent)
        if source in ("all", f["source"])
        and (verdict == "all" or f["prediction"].lower() == verdict)
    )

    return [row for _, row in zip(range(limit), rows)]


@app.get("/api/sources")
async def source_status():
    """Per source: flows scored so far and how long ago the last one came."""

    now = datetime.now()

    out = {}

    for source in SOURCES:

        stats = await asyncio.to_thread(hub.store.stats, source)

        seen = hub.last_seen.get(source)

        out[source] = {
            "flows": stats["total"],
            "alerts": stats["alerts"],
            "seconds_since_last": (
                None if seen is None else round((now - seen).total_seconds())
            )
        }

    return out


# -- alerts and their handling ---------------------------------------------

@app.get("/api/alerts")
async def list_alerts(
    status: str = "open",
    risk: str | None = None,
    attack_type: str | None = None,
    source: str | None = None,
    q: str | None = None,
    before_id: int | None = None,
    limit: int = Query(100, ge=1, le=500)
):

    return await asyncio.to_thread(
        lambda: hub.store.list_alerts(
            limit=limit, status=status, risk=risk, attack_type=attack_type,
            source=source, q=q, before_id=before_id
        )
    )


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: int):

    alert = await asyncio.to_thread(hub.store.get_alert, alert_id)

    if alert is None:
        raise HTTPException(404, "no such alert")

    return alert


class AlertUpdate(BaseModel):

    status: str | None = None
    assignee: str | None = None
    note: str | None = None
    actor: str = "analyst"


@app.patch("/api/alerts/{alert_id}")
async def update_alert(alert_id: int, update: AlertUpdate, request: Request):

    who = actor(request, update.actor)

    try:
        alert = await asyncio.to_thread(
            lambda: hub.store.update_alert(
                alert_id, update.status, update.assignee, update.note, who
            )
        )
    except ValueError as error:
        raise HTTPException(400, str(error))

    if alert is None:
        raise HTTPException(404, "no such alert")

    await hub.broadcast({"type": "alert_updated", "id": alert_id})

    return alert


class BulkUpdate(BaseModel):

    ids: list[int]
    status: str
    actor: str = "analyst"


@app.post("/api/alerts/bulk")
async def bulk_update(update: BulkUpdate, request: Request):

    try:
        changed = await asyncio.to_thread(
            hub.store.bulk_status, update.ids, update.status,
            actor(request, update.actor)
        )
    except ValueError as error:
        raise HTTPException(400, str(error))

    await hub.broadcast({"type": "alert_updated", "id": None})

    return {"changed": changed}


# -- notifications ----------------------------------------------------------

@app.get("/api/notifications")
async def notification_status():

    return await asyncio.to_thread(hub.notifier.status)


@app.get("/api/notifications/config")
async def notification_config():

    return await asyncio.to_thread(hub.notifier.settings)


@app.put("/api/notifications/config")
async def notification_config_save(settings: dict, request: Request):

    request.state.audit = "notification settings"

    try:
        saved = await asyncio.to_thread(hub.notifier.save_managed, settings)
    except SettingsError as error:
        raise HTTPException(400, str(error))
    except ValueError as error:
        raise HTTPException(500, str(error))

    return {"source": "dashboard", "settings": saved}


@app.post("/api/notifications/reload")
async def notification_reload():
    """Re-read notify.json so settings can change without a restart."""

    try:
        hub.notifier.reload()
    except (OSError, ValueError) as error:
        raise HTTPException(400, f"could not read notify.json: {error}")

    return await asyncio.to_thread(hub.notifier.status)


@app.post("/api/notifications/test")
async def notification_test():

    if not hub.notifier.channels():
        raise HTTPException(
            400, "no notification channel configured (see notify.example.json)"
        )

    return await asyncio.to_thread(hub.notifier.send, [], True)


# -- uploaded files and datasets --------------------------------------------------------

dataset_info = {}


def dataset_summary(name):
    """Label counts of one dataset CSV, cached until the file changes."""

    path = files.area_dir("dataset", data_dir()) / name

    stat = path.stat()

    key = (stat.st_size, int(stat.st_mtime))

    cached = dataset_info.get(name)

    if cached and cached["key"] == key:
        return cached

    labels = files.label_counts(path)

    dataset_info[name] = {"key": key, "labels": labels, "rows": sum(labels.values())}

    return dataset_info[name]


async def scan_dataset(name):
    """Count a dataset's labels in the background (large files take seconds)."""

    try:
        await asyncio.to_thread(dataset_summary, name)
        await hub.broadcast({"type": "files_changed"})
    except Exception as error:
        dataset_info[name] = {"key": None, "labels": None, "rows": None, "error": str(error)}


@app.get("/api/files")
async def list_files_api():

    out = {"max_upload_mb": files.max_bytes() // (1024 * 1024)}

    for area in files.AREAS:

        listing = await asyncio.to_thread(files.listing, area, data_dir())

        for entry in listing:

            if area == "dataset":

                info = dataset_info.get(entry["name"])

                fresh = info and info["key"] == (
                    entry["size"],
                    int(os.stat(files.area_dir(area, data_dir()) / entry["name"]).st_mtime)
                )

                if not fresh:
                    asyncio.create_task(scan_dataset(entry["name"]))

                entry["labels"] = info["labels"] if fresh else None
                entry["rows"] = info["rows"] if fresh else None
                entry["error"] = (info or {}).get("error")

        out[area] = listing

        out[f"{area}_dir"] = str(files.area_dir(area, data_dir()).resolve())

    return out


@app.put("/api/files/{area}/{name}")
async def upload_file(area: str, name: str, request: Request, replace: bool = False):
    """The file's bytes are the request body, streamed to disk."""

    try:
        files.check_name(area, name)
    except files.FileError as error:
        raise HTTPException(400, str(error))

    folder = files.area_dir(area, data_dir())

    folder.mkdir(parents=True, exist_ok=True)

    final = folder / name

    if final.exists() and not replace:
        raise HTTPException(409, f"{name} already exists (tick 'replace' to overwrite)")

    limit = files.max_bytes()

    if int(request.headers.get("content-length") or 0) > limit:
        raise HTTPException(
            413, f"larger than the {limit // (1024 * 1024)} MB limit",
            headers={"Connection": "close"}
        )

    partial = folder / f".{name}.part"

    size = 0

    try:

        with open(partial, "wb") as out:

            async for chunk in request.stream():

                size += len(chunk)

                if size > limit:

                    # "close" makes the server stop reading the rest of the
                    # stream instead of absorbing and discarding it
                    raise HTTPException(
                        413, f"larger than the {limit // (1024 * 1024)} MB limit",
                        headers={"Connection": "close"}
                    )

                out.write(chunk)

        if size == 0:
            raise HTTPException(400, "the file is empty")

        try:
            await asyncio.to_thread(files.check_content, area, name, partial)
        except files.FileError as error:
            raise HTTPException(400, str(error))

        os.replace(partial, final)

    finally:

        if partial.exists():
            partial.unlink()

    dataset_info.pop(name, None)

    request.state.audit = f"{area}/{name} ({size} bytes)"

    if area == "dataset":
        asyncio.create_task(scan_dataset(name))

    return {"name": name, "size": size}


@app.delete("/api/files/{area}/{name}")
async def delete_file(area: str, name: str, request: Request):

    try:
        files.check_name(area, name)
    except files.FileError as error:
        raise HTTPException(400, str(error))

    path = files.area_dir(area, data_dir()) / name

    if not path.is_file():
        raise HTTPException(404, "no such file")

    path.unlink()

    dataset_info.pop(name, None)

    request.state.audit = f"{area}/{name}"

    return {"ok": True}


# -- the server itself ---------------------------------------------------------------------

def server_facts():

    db = os.environ.get("IDS_DB", "ids.db")

    return {
        "pid": os.getpid(),
        "uptime_seconds": round(time.time() - hub.started),
        "started_at": datetime.fromtimestamp(hub.started).isoformat(timespec="seconds"),
        "python": sys.version.split()[0],
        "platform": f"{platform.system()} {platform.release()}",
        "command": " ".join(lifecycle.original_command()),
        "directory": os.getcwd(),
        "database": os.path.abspath(db),
        "database_bytes": os.path.getsize(db) if os.path.exists(db) else 0,
        "autostart": {
            "supported": hub.autostart.supported,
            "enabled": hub.autostart.enabled() if hub.autostart.supported else False
        }
    }


@app.get("/api/server")
async def server_info():

    return await asyncio.to_thread(server_facts)


class RestartOptions(BaseModel):

    behind_proxy: bool | None = None


@app.post("/api/server/restart")
async def server_restart(request: Request, options: RestartOptions | None = None):
    """Restart this server (same command line, or with proxy mode switched).
    The page reconnects by itself."""

    log.warning("restart requested by %s", request.state.who.name)

    loop = asyncio.get_running_loop()

    if options and options.behind_proxy is not None:

        command = lifecycle.original_command()

        if not any(part.endswith("serve.py") for part in command):
            raise HTTPException(
                400, "proxy mode can only be switched when the dashboard was started with serve.py"
            )

        command = lifecycle.with_flag(command, "--behind-proxy", options.behind_proxy)

        request.state.audit = "proxy mode " + ("on" if options.behind_proxy else "off")

        loop.call_later(
            0.7, lambda: lifecycle.restart(spawn=lambda: lifecycle.spawn_relauncher(command=command))
        )
    else:
        # respond first; then relaunch and exit
        loop.call_later(0.7, lifecycle.restart)

    return {"restarting": True}


class AutostartSwitch(BaseModel):

    enabled: bool


@app.post("/api/server/autostart")
async def server_autostart(switch: AutostartSwitch, request: Request):

    request.state.audit = "on" if switch.enabled else "off"

    if not hub.autostart.supported:
        raise HTTPException(400, "not supported on this platform")

    def apply():

        if switch.enabled:
            hub.autostart.enable(
                lifecycle.original_command(), os.getcwd(),
                os.path.join(os.getcwd(), "logs", "server.log")
            )
        else:
            hub.autostart.disable()

    try:
        await asyncio.to_thread(apply)
    except RuntimeError as error:
        raise HTTPException(500, str(error))

    return await asyncio.to_thread(server_facts)


@app.get("/api/backup")
async def backup():
    """A consistent copy of the database (alerts, users, settings)."""

    handle, path = tempfile.mkstemp(suffix=".db")

    os.close(handle)

    await asyncio.to_thread(hub.store.backup_to, path)

    return FileResponse(
        path, media_type="application/octet-stream",
        filename=f"ids-backup-{datetime.now():%Y%m%d-%H%M%S}.db",
        background=BackgroundTask(os.unlink, path)
    )


@app.get("/api/logs")
def server_logs(limit: int = Query(300, ge=1, le=2000), level: str = "INFO", after: int = 0):

    if level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise HTTPException(400, "level must be DEBUG, INFO, WARNING or ERROR")

    return hub.logs.recent(limit, level, after)


@app.get("/api/audit")
async def audit_log(limit: int = Query(200, ge=1, le=1000), before_id: int | None = None):

    return await asyncio.to_thread(hub.store.list_audit, limit, before_id)


# -- the HTTPS reverse proxy ---------------------------------------------------------------

async def proxy_call(function, *args):
    """Run a (blocking) proxy operation; its mistakes become 400s."""

    try:
        return await asyncio.to_thread(function, *args)
    except ProxyError as error:
        raise HTTPException(400, str(error))


def proxy_status():

    status = hub.proxy.status()

    status["dashboard_behind_proxy"] = started_behind_proxy()

    status["can_switch_proxy_mode"] = any(
        part.endswith("serve.py") for part in lifecycle.original_command()
    )

    return status


@app.get("/api/proxy")
async def proxy_info():

    return await asyncio.to_thread(proxy_status)


@app.put("/api/proxy/settings")
async def proxy_settings(settings: dict, request: Request):

    request.state.audit = f"{settings.get('engine', '')} {settings.get('address', '')}:{settings.get('port', '')}"

    await proxy_call(hub.proxy.save, settings)

    return await asyncio.to_thread(proxy_status)


class ProxyInstall(BaseModel):

    engine: str
    allow_unverified: bool = False


@app.post("/api/proxy/install")
async def proxy_install(body: ProxyInstall, request: Request):

    request.state.audit = body.engine

    manifest = await proxy_call(
        lambda: hub.proxy.install(body.engine, allow_unverified=body.allow_unverified)
    )

    log.info("installed %s %s (%s)", body.engine, manifest["version"], manifest["verified"])

    return await asyncio.to_thread(proxy_status)


@app.post("/api/proxy/start")
async def proxy_start(request: Request):

    await proxy_call(hub.proxy.start)

    log.info("proxy started: %s", hub.proxy.url())

    return await asyncio.to_thread(proxy_status)


@app.post("/api/proxy/stop")
async def proxy_stop(request: Request):

    await proxy_call(hub.proxy.stop)

    log.info("proxy stopped")

    return await asyncio.to_thread(proxy_status)


@app.post("/api/proxy/restart")
async def proxy_restart(request: Request):

    await proxy_call(hub.proxy.restart)

    return await asyncio.to_thread(proxy_status)


@app.post("/api/proxy/test")
async def proxy_test():

    return await proxy_call(hub.proxy.test)


@app.get("/api/proxy/log")
async def proxy_log(lines: int = Query(60, ge=1, le=500)):

    return {"log": await asyncio.to_thread(hub.proxy.log_tail, lines)}


@app.get("/api/proxy/certificate")
async def proxy_certificate():

    found = await proxy_call(hub.proxy.certificate)

    return {k: v for k, v in found.items() if k != "pem"}


@app.get("/api/proxy/certificate/download")
async def proxy_certificate_download():

    found = await proxy_call(hub.proxy.certificate)

    return Response(
        found["pem"], media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="ids-proxy-certificate.crt"'}
    )


# -- demo replay ----------------------------------------------------------

class ReplaySettings(BaseModel):

    running: bool | None = None
    rate: int | None = None


@app.post("/api/replay")
async def set_replay(settings: ReplaySettings):

    if settings.running:

        require_model()

        try:
            await load_demo()
        except FileNotFoundError as error:
            raise HTTPException(400, str(error))

    if settings.running is not None:
        hub.replay["running"] = settings.running

    if settings.rate is not None:
        hub.replay["rate"] = max(1, min(settings.rate, MAX_REPLAY_RATE))

    await hub.broadcast({"type": "replay", "replay": hub.replay})

    return hub.replay


@app.post("/api/reset")
async def reset():
    """Clear the demo replay's alerts and counters; real alerts stay."""

    async with hub.lock:

        await asyncio.to_thread(hub.store.clear_source, "replay")

        hub.reset_live("replay")

    await hub.broadcast({"type": "reset", "source": "replay"})

    return {"ok": True}


# -- API ingest settings ---------------------------------------------------

def key_required():

    return bool(env_api_key() or hub.store.get_setting("api_key_hash"))


def key_valid(supplied):
    """Matches the environment key or the one created in the dashboard."""

    if not supplied:
        return False

    env = env_api_key()

    if env and hmac.compare_digest(supplied, env):
        return True

    stored = hub.store.get_setting("api_key_hash")

    return bool(stored) and hmac.compare_digest(digest_key(supplied), stored)


@app.get("/api/ingest")
def ingest_status():

    return {
        "enabled": bool(hub.store.get_setting("api_ingest_enabled", True)),
        "key_required": key_required(),
        "key_source": (
            "environment" if env_api_key()
            else "dashboard" if hub.store.get_setting("api_key_hash")
            else None
        ),
        "max_flows_per_request": MAX_FLOWS_PER_REQUEST
    }


class IngestSwitch(BaseModel):

    enabled: bool


@app.post("/api/ingest")
async def ingest_switch(switch: IngestSwitch):

    hub.store.set_setting("api_ingest_enabled", switch.enabled)

    await hub.broadcast({"type": "ingest_changed"})

    return ingest_status()


@app.post("/api/ingest/key")
async def ingest_new_key():
    """Create (or rotate) the API key. It is shown once; only a hash is kept."""

    if env_api_key():
        raise HTTPException(
            409, "the key is set by IDS_API_KEY; change it there"
        )

    key = secrets.token_urlsafe(24)

    hub.store.set_setting("api_key_hash", digest_key(key))

    return {"key": key, **ingest_status()}


@app.delete("/api/ingest/key")
async def ingest_remove_key():

    if env_api_key():
        raise HTTPException(
            409, "the key is set by IDS_API_KEY; remove it there"
        )

    hub.store.delete_setting("api_key_hash")

    return ingest_status()


# -- capture control -------------------------------------------------------

@app.get("/api/capture")
def capture_status():

    return hub.capture.status()


@app.get("/api/capture/options")
async def capture_options():

    return {
        "interfaces": await asyncio.to_thread(list_interfaces),
        "files": list_files(data_dir()),
        "data_dir": str(Path(data_dir()).resolve()),
        "environment": await asyncio.to_thread(diagnose),
        "saved": hub.store.get_setting("capture_config")
    }


class CaptureStart(BaseModel):

    mode: str
    target: str


@app.post("/api/capture/start")
async def capture_start(body: CaptureStart, request: Request):

    request.state.audit = f"{body.mode}: {body.target}"

    require_model()

    try:
        await asyncio.to_thread(hub.capture.start, body.mode, body.target)
    except ValueError as error:
        raise HTTPException(400, str(error))
    except RuntimeError as error:
        raise HTTPException(409, str(error))

    return hub.capture.status()


@app.post("/api/capture/stop")
async def capture_stop():

    await asyncio.to_thread(hub.capture.stop)

    return hub.capture.status()


class AutoStart(BaseModel):

    enabled: bool


@app.post("/api/capture/autostart")
async def capture_autostart(setting: AutoStart):

    hub.capture.set_autostart(setting.enabled)

    return hub.capture.status()


# -- ingest ---------------------------------------------------------------

@app.post("/api/score")
async def score(
    flows: list[dict],
    source: str = "api",
    x_api_key: str | None = Header(default=None)
):
    """Score flows from any exporter (CICFlowMeter column names)."""

    if not hub.store.get_setting("api_ingest_enabled", True):
        raise HTTPException(503, "API ingest is switched off")

    require_model()

    if key_required() and not key_valid(x_api_key):
        raise HTTPException(401, "missing or wrong X-API-Key")

    if source not in ("api", "capture"):
        raise HTTPException(400, "source must be 'api' or 'capture'")

    if not flows:
        raise HTTPException(400, "expected a non-empty list of flows")

    if len(flows) > MAX_FLOWS_PER_REQUEST:
        raise HTTPException(
            413, f"at most {MAX_FLOWS_PER_REQUEST} flows per request"
        )

    try:
        result, records = await ingest(pd.DataFrame(flows), source=source)
    except ValueError as error:
        raise HTTPException(400, str(error))

    return {
        "scored": len(result),
        "alerts": [public(r) for r in records]
    }


@app.websocket("/ws")
async def websocket(ws: WebSocket):

    who = await asyncio.to_thread(principal_for, ws.query_params.get("token"))

    if who is None:
        await ws.close(code=1008)
        return

    await ws.accept()

    hub.clients.add(ws)

    await ws.send_text(json.dumps({
        "type": "hello",
        "replay": hub.replay,
        "ticks": list(hub.ticks),
        "capture": hub.capture.status(),
        "drift": {s: m.report() for s, m in hub.drift.items()}
    }))

    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        hub.clients.discard(ws)


# Built React app (npm run build in frontend/)
if FRONTEND.exists():

    app.mount(
        "/assets",
        StaticFiles(directory=FRONTEND / "assets"),
        name="assets"
    )

    @app.get("/{path:path}")
    def spa(path: str):

        file = FRONTEND / path

        return FileResponse(
            file if file.is_file() else FRONTEND / "index.html"
        )
