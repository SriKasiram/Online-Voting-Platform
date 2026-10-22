"""FastAPI application. Every route lives under /api, matching the frontend's dev proxy."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import select

from app.deps import DbSession, get_db
from app.models import Division
from app.rbac import check_admin_routes
from app.roll_signing import check_roll_at_startup
from app.routers import admin, auth, ballot, register
from app.schemas import DivisionOut


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # SR-02: the API refuses to start unless every electoral roll record's signature checks out.
    # Uses the routes' database dependency, so tests check their own database.
    sessions = app.dependency_overrides.get(get_db, get_db)()
    try:
        check_roll_at_startup(next(sessions))
    finally:
        sessions.close()
    yield


app = FastAPI(title="Electronic voting prototype API", version="0.1.0", lifespan=lifespan)

app.include_router(auth.router, prefix="/api")
app.include_router(ballot.router, prefix="/api")
app.include_router(register.router, prefix="/api")
# SR-05: staff routes, all declared through AdminRouter
app.include_router(admin.router, prefix="/api")


@app.get("/api/health", tags=["health"])
def health() -> dict[str, str]:
    """Liveness check. Reports status only, so it reveals nothing about the system."""
    return {"status": "ok"}


@app.get("/api/divisions", tags=["divisions"])
def list_divisions(db: DbSession) -> list[DivisionOut]:
    """Every electoral division, sorted by name."""
    return [DivisionOut.model_validate(d) for d in db.scalars(select(Division).order_by(Division.name))]


# SR-05: last, once every route exists. Refuses to start if any /api/admin route lacks a mapped
# permission. There is no setting to skip it.
check_admin_routes(app)
