"""Push notifications to a person's own devices: the server's public key, subscribing, unsubscribing, a test."""
import asyncio

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

import webpush
from api_core import hub

router = APIRouter()


def owner(request):
    """The name a device is registered under: the signed-in person, or "local" on an open dashboard."""

    who = request.state.who

    return "local" if who.via == "open" else who.name


class Subscription(BaseModel):

    subscription: dict


class Endpoint(BaseModel):

    endpoint: str


@router.get("/api/push")
async def push_status(request: Request):
    """The server's public key (a browser needs it to subscribe) and how many devices this person has."""

    return await asyncio.to_thread(hub.push.status, owner(request))


@router.post("/api/push/subscribe")
async def push_subscribe(body: Subscription, request: Request):

    request.state.audit = "device added"

    try:
        devices = await asyncio.to_thread(hub.push.subscribe, owner(request), body.subscription)
    except webpush.PushError as error:
        raise HTTPException(400, str(error))

    return {"devices": devices}


@router.post("/api/push/unsubscribe")
async def push_unsubscribe(body: Endpoint, request: Request):

    request.state.audit = "device removed"

    return {"devices": await asyncio.to_thread(hub.push.unsubscribe, owner(request), body.endpoint)}


@router.post("/api/push/test")
async def push_test(request: Request):
    """Send a test notification to this person's devices."""

    name = owner(request)

    if not await asyncio.to_thread(hub.store.list_push, name):
        raise HTTPException(400, "no device of yours is registered for push notifications")

    counts = await asyncio.to_thread(
        hub.push.notify, "Test notification", "If you can read this, push notifications reach this device.", "/",
        [name]
    )

    return counts
