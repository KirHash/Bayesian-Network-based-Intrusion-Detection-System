"""Backups: list, make one now, download, upload, restore and delete (administrators only)."""
import asyncio
import os
import tempfile
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from accounts import hash_token
from api_core import bearer, hub, log, security_event
from backups import MAX_UPLOAD, BackupError

router = APIRouter()


def manager():

    if hub.backups is None:
        raise HTTPException(503, "backups are not available yet")

    return hub.backups


def plain(error):
    """A BackupError is already a sentence for the person."""

    return HTTPException(400, str(error))


@router.get("/api/backups")
async def list_backups():

    backups = manager()

    return {
        "backups": await asyncio.to_thread(backups.list),
        "keep": backups.keep,
        "folder": os.path.abspath(backups.directory),
        "last_error": backups.last_error,
        "due": await asyncio.to_thread(backups.due)
    }


@router.post("/api/backups")
async def make_backup(request: Request):

    try:
        row = await asyncio.to_thread(manager().create, "manual")
    except BackupError as error:
        raise plain(error)
    except OSError as error:
        raise HTTPException(500, f"the backup could not be written: {error.strerror or error}")

    request.state.audit = row["name"]

    return row


@router.get("/api/backups/{name}")
async def download_backup(name: str):

    try:
        path = manager().path(name)
    except BackupError as error:
        raise HTTPException(404, str(error))

    return FileResponse(path, media_type="application/octet-stream", filename=name)


@router.delete("/api/backups/{name}")
async def delete_backup(name: str, request: Request):

    try:
        await asyncio.to_thread(manager().delete, name)
    except BackupError as error:
        raise HTTPException(404, str(error))

    request.state.audit = name

    return {"deleted": name}


@router.post("/api/backups/upload")
async def upload_backup(request: Request):
    """The raw bytes of a backup file. It is checked before it is kept; restoring it is a separate step."""

    backups = manager()

    declared = request.headers.get("content-length")

    if declared and declared.isdigit() and int(declared) > MAX_UPLOAD:
        raise HTTPException(413, "that file is too large to be a backup")

    handle, partial = tempfile.mkstemp(suffix=".part", dir=backups.directory)

    size = 0

    try:
        with os.fdopen(handle, "wb") as out:

            async for chunk in request.stream():

                size += len(chunk)

                if size > MAX_UPLOAD:
                    raise HTTPException(413, "that file is too large to be a backup")

                out.write(chunk)

        if not size:
            raise HTTPException(400, "the file is empty")

        try:
            row, facts = await asyncio.to_thread(backups.add_upload, partial)
        except BackupError as error:
            raise plain(error)
    finally:
        if os.path.exists(partial):
            os.unlink(partial)

    request.state.audit = row["name"]

    return {**row, **facts}


@router.post("/api/backups/{name}/restore")
async def restore_backup(name: str, request: Request):
    """Replace everything with this backup. A copy of the current state is kept first."""

    who = request.state.who

    try:
        result = await asyncio.to_thread(manager().restore, name, hash_token(bearer(request)))
    except BackupError as error:
        raise plain(error)
    except OSError as error:
        raise HTTPException(500, f"the restore could not be completed: {error.strerror or error}")

    log.warning("database restored from %s by %s", name, who.name)

    request.state.audit = f"restored {name}"

    # written after the restore, so the record survives in the restored database
    await asyncio.to_thread(security_event, "restore", f"{who.name} restored the database from {name}")

    result["signed_out"] = "everyone else"

    return result
