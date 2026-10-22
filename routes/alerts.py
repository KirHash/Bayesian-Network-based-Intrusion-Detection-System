"""Statistics, drift, recent flows, sources and the alerts with their handling."""
import asyncio
import csv
import io
import ipaddress
import socket
import time
from datetime import datetime
from fastapi import Request, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from fastapi import APIRouter
from api_core import (
    MAX_RECENT,
    OPEN,
    SOURCES,
    hub
)

router = APIRouter()


def actor(request, fallback="analyst"):
    """Name recorded in the alert history for a change."""

    who = getattr(request.state, "who", OPEN)

    return fallback if who.via == "open" else who.name


@router.get("/api/stats")
async def get_stats(source: str = "all"):

    stats = await asyncio.to_thread(hub.store.stats, source)

    return {
        **stats,
        **hub.accuracy(source),
        "replay": hub.replay
    }


@router.get("/api/drift")
def get_drift(source: str = "all"):

    wanted = [s for s in SOURCES if source in ("all", s)]

    return {s: hub.drift_monitor(s).report() for s in wanted if s in hub.drift}


@router.get("/api/drift/history")
def drift_history(source: str = "all"):
    """How drift moved over time: a point every few seconds while traffic flows, per source."""

    wanted = [s for s in SOURCES if source in ("all", s)]

    return {s: list(hub.drift_history[s]) for s in wanted}


@router.get("/api/flows")
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


@router.get("/api/sources")
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


@router.get("/api/alerts")
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


EXPORT_COLUMNS = (
    "id", "time", "source", "attack_type", "reason", "risk", "probability", "surprise", "label",
    "src_ip", "dst_ip", "dst_port", "status", "assignee", "note", "updated_at"
)

# most rows one export holds; a spreadsheet gives up long before this
MAX_EXPORT_ROWS = 100_000


def csv_cell(value):
    """A value safe to open in a spreadsheet: text that would run as a formula is defused.

    Alerts carry text an attacker can influence (addresses, a note someone typed); a cell starting with
    = + - @ or a tab is a formula to Excel and LibreOffice."""

    if value is None:
        return ""

    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value

    return value


def csv_rows(filters, limit):
    """The CSV text of matching alerts, newest first, in pages (the table is never held whole)."""

    out = io.StringIO()

    writer = csv.writer(out)

    writer.writerow(EXPORT_COLUMNS)

    yield out.getvalue()

    sent = 0
    before = None

    while sent < limit:

        page = hub.store.list_alerts(limit=min(1000, limit - sent), before_id=before, **filters)

        if not page:
            return

        out.seek(0)
        out.truncate()

        for row in page:
            writer.writerow([csv_cell(row.get(column)) for column in EXPORT_COLUMNS])

        sent += len(page)
        before = page[-1]["id"]

        yield out.getvalue()


@router.get("/api/alerts/export")
async def export_alerts(
    request: Request,
    status: str = "all",
    risk: str | None = None,
    attack_type: str | None = None,
    source: str | None = None,
    q: str | None = None,
    limit: int = Query(MAX_EXPORT_ROWS, ge=1, le=MAX_EXPORT_ROWS)
):
    """The alerts the table shows (same filters) as a CSV file, up to `limit` rows."""

    filters = {"status": status, "risk": risk, "attack_type": attack_type, "source": source, "q": q}

    shown = ", ".join(f"{k}={v}" for k, v in filters.items() if v not in (None, "", "all"))

    await asyncio.to_thread(
        hub.store.add_audit, actor(request, "local"), "export alerts", shown or "all alerts"
    )

    name = f"alerts-{datetime.now():%Y%m%d-%H%M%S}.csv"

    return StreamingResponse(
        csv_rows(filters, limit),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"}
    )


# -- what an address is, and (on request) its name ---------------------------------------------------

LOOKUP_SECONDS = 3.0

LOOKUP_KEEP = 3600

# {address: (when, name or None)}; a name rarely changes within the hour
name_cache = {}


def ip_kind(text):
    """What sort of address this is: private, loopback, link-local, multicast, reserved or public."""

    ip = ipaddress.ip_address(text)

    if ip.is_loopback:
        return "loopback"

    if ip.is_link_local:
        return "link-local"

    if ip.is_multicast:
        return "multicast"

    if ip.is_unspecified or ip.is_reserved:
        return "reserved"

    if ip.is_private:
        return "private"

    return "public"


@router.get("/api/lookup/{address}")
async def lookup_address(address: str):
    """The kind of an address and, for a public one, its reverse-DNS name (the only thing looked up).

    Private addresses are never sent to a resolver: their names are nobody else's business. A slow or
    failing resolver gives no name rather than an error."""

    try:
        kind = ip_kind(address)
    except ValueError:
        raise HTTPException(400, "that is not an IP address")

    if kind != "public":
        return {"address": address, "kind": kind, "name": None}

    now = time.time()

    cached = name_cache.get(address)

    if cached and now - cached[0] < LOOKUP_KEEP:
        return {"address": address, "kind": kind, "name": cached[1]}

    def resolve():
        try:
            return socket.gethostbyaddr(address)[0]
        except (OSError, UnicodeError):
            return None

    try:
        name = await asyncio.wait_for(asyncio.to_thread(resolve), LOOKUP_SECONDS)
    except asyncio.TimeoutError:
        name = None

    if len(name_cache) > 1000:
        name_cache.clear()

    name_cache[address] = (now, name)

    return {"address": address, "kind": kind, "name": name}


@router.get("/api/alerts/{alert_id}")
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


@router.patch("/api/alerts/{alert_id}")
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


@router.post("/api/alerts/bulk")
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
