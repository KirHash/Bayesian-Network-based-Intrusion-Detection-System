"""The managed HTTPS reverse proxy."""
import asyncio
from fastapi import Request, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
import lifecycle
from proxy_manager import ProxyError
from fastapi import APIRouter
from api_core import (
    hub,
    log,
    started_behind_proxy
)

router = APIRouter()


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


@router.get("/api/proxy")
async def proxy_info():

    return await asyncio.to_thread(proxy_status)


@router.put("/api/proxy/settings")
async def proxy_settings(settings: dict, request: Request):

    request.state.audit = f"{settings.get('engine', '')} {settings.get('address', '')}:{settings.get('port', '')}"

    await proxy_call(hub.proxy.save, settings)

    return await asyncio.to_thread(proxy_status)


class ProxyInstall(BaseModel):

    engine: str
    allow_unverified: bool = False


@router.post("/api/proxy/install")
async def proxy_install(body: ProxyInstall, request: Request):

    request.state.audit = body.engine

    manifest = await proxy_call(
        lambda: hub.proxy.install(body.engine, allow_unverified=body.allow_unverified)
    )

    log.info("installed %s %s (%s)", body.engine, manifest["version"], manifest["verified"])

    return await asyncio.to_thread(proxy_status)


@router.post("/api/proxy/start")
async def proxy_start(request: Request):

    await proxy_call(hub.proxy.start)

    log.info("proxy started: %s", hub.proxy.url())

    return await asyncio.to_thread(proxy_status)


@router.post("/api/proxy/stop")
async def proxy_stop(request: Request):

    await proxy_call(hub.proxy.stop)

    log.info("proxy stopped")

    return await asyncio.to_thread(proxy_status)


@router.post("/api/proxy/restart")
async def proxy_restart(request: Request):

    await proxy_call(hub.proxy.restart)

    return await asyncio.to_thread(proxy_status)


@router.post("/api/proxy/test")
async def proxy_test():

    return await proxy_call(hub.proxy.test)


@router.get("/api/proxy/log")
async def proxy_log(lines: int = Query(60, ge=1, le=500)):

    return {"log": await asyncio.to_thread(hub.proxy.log_tail, lines)}


@router.get("/api/proxy/certificate")
async def proxy_certificate():

    found = await proxy_call(hub.proxy.certificate)

    return {k: v for k, v in found.items() if k != "pem"}


@router.get("/api/proxy/certificate/download")
async def proxy_certificate_download():

    found = await proxy_call(hub.proxy.certificate)

    return Response(
        found["pem"], media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="ids-proxy-certificate.crt"'}
    )
