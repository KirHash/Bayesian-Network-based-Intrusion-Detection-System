"""Webhook and e-mail notification settings."""
import asyncio
from fastapi import Request, HTTPException
from notifier import SettingsError
from fastapi import APIRouter
from api_core import (
    hub
)

router = APIRouter()


@router.get("/api/notifications")
async def notification_status():

    return await asyncio.to_thread(hub.notifier.status)


@router.get("/api/notifications/config")
async def notification_config():

    return await asyncio.to_thread(hub.notifier.settings)


@router.put("/api/notifications/config")
async def notification_config_save(settings: dict, request: Request):

    request.state.audit = "notification settings"

    try:
        saved = await asyncio.to_thread(hub.notifier.save_managed, settings)
    except SettingsError as error:
        raise HTTPException(400, str(error))
    except ValueError as error:
        raise HTTPException(500, str(error))

    return {"source": "dashboard", "settings": saved}


@router.post("/api/notifications/reload")
async def notification_reload():
    """Re-read notify.json so settings can change without a restart."""

    try:
        hub.notifier.reload()
    except (OSError, ValueError) as error:
        raise HTTPException(400, f"could not read notify.json: {error}")

    return await asyncio.to_thread(hub.notifier.status)


@router.post("/api/notifications/test")
async def notification_test():

    if not hub.notifier.channels():
        raise HTTPException(
            400, "no notification channel configured (see notify.example.json)"
        )

    return await asyncio.to_thread(hub.notifier.send, [], True)
