"""The trained model (information, forest switch, reload, roll back) and the background jobs that retrain it."""
import asyncio
import glob
import os
from fastapi import Request, HTTPException
from pydantic import BaseModel
from bayesian_engine import model_path
from jobs import KINDS, JobBusy
from data_loader import dataset_glob
from fastapi import APIRouter
from api_core import (
    NO_MODEL,
    hub,
    reload_model,
    require_model
)

router = APIRouter()


@router.get("/api/model")
def model_info():

    if hub.detector is None:
        return {
            "trained": False, "threshold": None, "classes": [], "features": 0,
            "feature_edges": 0, "card": {}, "message": NO_MODEL,
            "forest": {"available": False, "confirm": False},
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
        "forest": {
            "available": hub.detector.forest is not None,
            "confirm": hub.detector.use_forest
        },
        # libraries whose versions differ from those that trained this model (empty when all match)
        "library_mismatch": hub.detector.library_mismatch,
        "previous_available": os.path.exists(model_path() + ".previous"),
        "dataset_files": len(glob.glob(dataset_glob()))
    }


class ForestSwitch(BaseModel):

    confirm: bool


@router.put("/api/model/forest")
async def model_forest(switch: ForestSwitch, request: Request):
    """Turn the forest's confirmation of classifier alerts on or off (its opinion is still recorded)."""

    require_model()

    if hub.detector.forest is None:
        raise HTTPException(400, "this model has no random forest: retrain to get one")

    request.state.audit = "confirm on" if switch.confirm else "confirm off"

    await asyncio.to_thread(hub.store.set_setting, "forest_confirm", switch.confirm)

    hub.detector.use_forest = switch.confirm

    return {"available": True, "confirm": switch.confirm}


@router.post("/api/model/reload")
async def model_reload(request: Request):
    """Load bayesian_ids.pkl again, e.g. after replacing the file by hand."""

    try:
        await asyncio.to_thread(reload_model)
    except Exception as error:
        raise HTTPException(400, f"could not load the model file: {error}")

    await hub.broadcast({"type": "model_changed"})

    return model_info()


@router.post("/api/model/rollback")
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


class JobStart(BaseModel):

    kind: str


@router.get("/api/jobs")
def list_jobs():

    return {"jobs": hub.jobs.recent(), "kinds": {
        k: {"title": v["title"], "needs_dataset": v["needs_dataset"]}
        for k, v in KINDS.items()
    }}


@router.post("/api/jobs")
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


@router.get("/api/jobs/{job_id}")
def job_output(job_id: int, after: int = 0):

    found = hub.jobs.get(job_id)

    if found is None:
        raise HTTPException(404, "no such job")

    return found.tail(after)


@router.post("/api/jobs/{job_id}/cancel")
async def cancel_job(job_id: int, request: Request):

    if not await asyncio.to_thread(hub.jobs.cancel, job_id):
        raise HTTPException(409, "that job is not running")

    request.state.audit = f"job {job_id}"

    return {"ok": True}
