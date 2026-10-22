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
import json
import os
import pickle
import secrets
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
import files
import logbuffer
from accounts import RANK, Accounts
from bayesian_engine import model_path
from jobs import KINDS, JobManager
from secrets_store import SecretBox
from capture_manager import CaptureManager
from detector import Detector
from notifier import Notifier
from proxy_manager import ProxyError, ProxyManager
from pushservice import PushService
from storage import Store
import api_core as core
from api_core import (
    CONTENT_SECURITY_POLICY,
    FRONTEND,
    OPEN,
    PUBLIC,
    UNAUDITED,
    auth_required,
    bearer,
    cors_origins,
    data_dir,
    forest_confirm_setting,
    hub,
    ingest,
    log,
    principal_for,
    prune_loop,
    redeem_ticket,
    reload_model,
    replay_loop,
    required_role,
    security_event
)
from backups import KEEP_AUTOMATIC, BackupManager
from routes import accounts, alerts, backups as backups_routes, model, notifications, proxy, push, server, sources, uploads


@asynccontextmanager
async def lifespan(app):

    # a new run starts from a clean state (the hub outlives a reload of this module; its asyncio
    # locks belong to one event loop)
    hub.__init__()

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

    if hub.detector is not None:
        hub.detector.use_forest = bool(hub.detector.forest and forest_confirm_setting())

    hub.secrets = SecretBox(db_path + ".key")

    await asyncio.to_thread(hub.store.prune_audit)

    log.info("server started (%s)", (
        "model trained " + hub.detector.bundle.get("card", {}).get("trained_at", "unknown")
        if hub.detector else "no model yet"
    ))

    hub.accounts = Accounts(hub.store, box=hub.secrets, on_event=security_event)

    hub.backups = BackupManager(
        hub.store,
        os.environ.get("IDS_BACKUP_DIR") or os.path.join(os.path.dirname(os.path.abspath(db_path)), "backups"),
        keep=os.environ.get("IDS_BACKUP_KEEP") or KEEP_AUTOMATIC
    )
    hub.backups.start()

    hub.push = PushService(hub.store, box=hub.secrets)

    hub.notifier = Notifier(hub.store, box=hub.secrets)
    hub.notifier.push = hub.push
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
        hub.store, core.dashboard_upstream,
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

    hub.backups.close()

    hub.store.close()


app = FastAPI(title="Bayesian IDS", lifespan=lifespan)

for module in (accounts, alerts, backups_routes, model, notifications, proxy, push, server, sources, uploads):
    app.include_router(module.router)


@app.exception_handler(StarletteHTTPException)
async def http_error(request, error):
    """HTTP errors as JSON; an unknown API address says so whether or not the dashboard is built."""

    detail = error.detail

    if error.status_code == 404 and detail == "Not Found" and request.url.path.startswith("/api"):
        detail = "no such API endpoint"

    return JSONResponse({"detail": detail}, status_code=error.status_code, headers=getattr(error, "headers", None))


@app.exception_handler(RequestValidationError)
async def invalid_request(request, error):
    """One readable sentence instead of a list of validation records."""

    first = error.errors()[0] if error.errors() else {}

    where = ".".join(str(part) for part in first.get("loc", ()) if part not in ("body", "query", "path"))

    message = first.get("msg", "the request is not valid").removeprefix("Value error, ")

    return JSONResponse({"detail": f"{where}: {message}" if where else message}, status_code=422)


@app.exception_handler(Exception)
async def unexpected_error(request, error):
    """A bug or a failing disk: tell the person it was not their fault, with a reference to find it in the log."""

    reference = secrets.token_hex(4)

    log.error("unexpected error %s on %s %s", reference, request.method, request.url.path, exc_info=error)

    return JSONResponse(
        {
            "detail": f"Something went wrong on the server. Nothing you did caused it. Reference {reference}: "
                      "an administrator can find it under Operations, Logs.",
            "reference": reference
        },
        status_code=500
    )


@app.middleware("http")
async def check_access(request, call_next):

    path = request.url.path

    if not path.startswith("/api/") or (request.method, path) in PUBLIC:
        return await call_next(request)

    client = request.client.host if request.client else "?"

    wait = hub.token_guesses.blocked(client)

    if wait:
        return JSONResponse(
            {"detail": "too many rejected tokens from this address; try again later"},
            status_code=429, headers={"Retry-After": str(wait)}
        )

    who = await asyncio.to_thread(principal_for, bearer(request))

    if who is None:

        # a request with no token at all is just someone who has not signed in; a wrong one is a guess
        if bearer(request) and hub.token_guesses.fail(client):
            await asyncio.to_thread(
                security_event, "token guessing", f"many rejected access tokens from {client}"
            )

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


@app.middleware("http")
async def security_headers(request, call_next):
    """Headers that make a browser refuse framing, sniffing and foreign scripts."""

    response = await call_next(request)

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")

    # answers from the API carry tokens, alerts and settings: nothing should keep a copy
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
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


if cors_origins():

    # added last, so it is outermost and answers preflight requests before sign-in is asked
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins(),
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600
    )


@app.websocket("/ws")
async def websocket(ws: WebSocket):

    # a ticket from POST /api/ws-ticket; a dashboard with no sign-in needs none
    ticket = ws.query_params.get("ticket")

    who = redeem_ticket(ticket) if ticket else (OPEN if not auth_required() else None)

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

        # an unknown API address is an error, not the dashboard's page
        if path == "api" or path.startswith("api/"):
            raise HTTPException(404, "no such API endpoint")

        file = FRONTEND / path

        return FileResponse(
            file if file.is_file() else FRONTEND / "index.html"
        )
