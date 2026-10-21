"""FastAPI application. Every route lives under /api, matching the frontend's dev proxy."""

from fastapi import FastAPI
from sqlalchemy import select

from app.deps import DbSession
from app.models import Division
from app.routers import auth, ballot, register
from app.schemas import DivisionOut

app = FastAPI(title="Electronic voting prototype API", version="0.1.0")

app.include_router(auth.router, prefix="/api")
app.include_router(ballot.router, prefix="/api")
app.include_router(register.router, prefix="/api")


@app.get("/api/health", tags=["health"])
def health() -> dict[str, str]:
    """Liveness check. Reports status only, so it reveals nothing about the system."""
    return {"status": "ok"}


@app.get("/api/divisions", tags=["divisions"])
def list_divisions(db: DbSession) -> list[DivisionOut]:
    """Every electoral division, sorted by name."""
    return [DivisionOut.model_validate(d) for d in db.scalars(select(Division).order_by(Division.name))]
