"""The server itself: health, restart, start at login, backup, logs and the audit trail."""
import asyncio
import os
import platform
import sys
import tempfile
import time
from datetime import datetime
from fastapi import Request, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from starlette.background import BackgroundTask
from pydantic import BaseModel
import lifecycle
from fastapi import APIRouter
from api_core import (
    hub,
    launcher_command,
    log
)

router = APIRouter()


@router.api_route("/api/healthz", methods=["GET", "HEAD"])
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


@router.get("/api/server")
async def server_info():

    return await asyncio.to_thread(server_facts)


class RestartOptions(BaseModel):

    behind_proxy: bool | None = None


@router.post("/api/server/restart")
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


@router.post("/api/server/autostart")
async def server_autostart(switch: AutostartSwitch, request: Request):

    request.state.audit = "on" if switch.enabled else "off"

    if not hub.autostart.supported:
        raise HTTPException(400, "not supported on this platform")

    def apply():

        if switch.enabled:
            hub.autostart.enable(
                launcher_command() or lifecycle.original_command(), os.getcwd(),
                os.path.join(os.getcwd(), "logs", "server.log")
            )
        else:
            hub.autostart.disable()

    try:
        await asyncio.to_thread(apply)
    except RuntimeError as error:
        raise HTTPException(500, str(error))

    return await asyncio.to_thread(server_facts)


@router.get("/api/backup")
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


@router.get("/api/logs")
def server_logs(limit: int = Query(300, ge=1, le=2000), level: str = "INFO", after: int = 0):

    if level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise HTTPException(400, "level must be DEBUG, INFO, WARNING or ERROR")

    return hub.logs.recent(limit, level, after)


@router.get("/api/audit")
async def audit_log(limit: int = Query(200, ge=1, le=1000), before_id: int | None = None):

    return await asyncio.to_thread(hub.store.list_audit, limit, before_id)
