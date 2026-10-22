"""Uploaded datasets and capture files."""
import asyncio
import os
from fastapi import Request, HTTPException
import files
from fastapi import APIRouter
from api_core import (
    data_dir,
    hub
)

router = APIRouter()


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


@router.get("/api/files")
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


@router.put("/api/files/{area}/{name}")
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


@router.delete("/api/files/{area}/{name}")
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
