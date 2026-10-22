"""Where flows come from: demo replay, API ingest settings and keys, capture control and /api/score."""
import asyncio
import hmac
import secrets
from pathlib import Path
import pandas as pd
from fastapi import Request, Header, HTTPException
from pydantic import BaseModel
from capture_manager import list_files, list_interfaces
from platform_check import diagnose
from fastapi import APIRouter
from api_core import (
    MAX_FLOWS_PER_REQUEST,
    MAX_REPLAY_RATE,
    data_dir,
    digest_key,
    env_api_key,
    hub,
    ingest,
    load_demo,
    public,
    require_model,
    security_event
)

router = APIRouter()


class ReplaySettings(BaseModel):

    running: bool | None = None
    rate: int | None = None


@router.post("/api/replay")
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


@router.post("/api/reset")
async def reset():
    """Clear the demo replay's alerts and counters; real alerts stay."""

    async with hub.lock:

        await asyncio.to_thread(hub.store.clear_source, "replay")

        hub.reset_live("replay")

    await hub.broadcast({"type": "reset", "source": "replay"})

    return {"ok": True}


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


@router.get("/api/ingest")
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


@router.post("/api/ingest")
async def ingest_switch(switch: IngestSwitch):

    hub.store.set_setting("api_ingest_enabled", switch.enabled)

    await hub.broadcast({"type": "ingest_changed"})

    return ingest_status()


@router.post("/api/ingest/key")
async def ingest_new_key():
    """Create (or rotate) the API key. It is shown once; only a hash is kept."""

    if env_api_key():
        raise HTTPException(
            409, "the key is set by IDS_API_KEY; change it there"
        )

    key = secrets.token_urlsafe(24)

    hub.store.set_setting("api_key_hash", digest_key(key))

    return {"key": key, **ingest_status()}


@router.delete("/api/ingest/key")
async def ingest_remove_key():

    if env_api_key():
        raise HTTPException(
            409, "the key is set by IDS_API_KEY; remove it there"
        )

    hub.store.delete_setting("api_key_hash")

    return ingest_status()


@router.get("/api/capture")
def capture_status():

    return hub.capture.status()


@router.get("/api/capture/options")
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


@router.post("/api/capture/start")
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


@router.post("/api/capture/stop")
async def capture_stop():

    await asyncio.to_thread(hub.capture.stop)

    return hub.capture.status()


class AutoStart(BaseModel):

    enabled: bool


@router.post("/api/capture/autostart")
async def capture_autostart(setting: AutoStart):

    hub.capture.set_autostart(setting.enabled)

    return hub.capture.status()


@router.post("/api/score")
async def score(
    flows: list[dict],
    request: Request,
    source: str = "api",
    x_api_key: str | None = Header(default=None)
):
    """Score flows from any exporter (CICFlowMeter column names)."""

    if not hub.store.get_setting("api_ingest_enabled", True):
        raise HTTPException(503, "API ingest is switched off")

    require_model()

    if key_required():

        client = request.client.host if request.client else "?"

        wait = hub.key_guesses.blocked(client)

        if wait:
            raise HTTPException(429, "too many wrong API keys from this address", headers={"Retry-After": str(wait)})

        if not key_valid(x_api_key):

            if x_api_key and hub.key_guesses.fail(client):
                await asyncio.to_thread(security_event, "api key guessing", f"many wrong API keys from {client}")

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
