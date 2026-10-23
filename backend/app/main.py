"""FastAPI application. Every route lives under /api, matching the frontend's dev proxy."""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

# SR-19: what the health probe checks
from app import health as app_health
# SR-11: no usable ballot key, no API
from app.ballot_crypto import check_ballot_key_at_startup
from app.ballot_definitions import check_definitions_at_startup
# SR-10: the HSTS lifetime, and where the built frontend is
from app.config import PROJECT_DIR, settings
from app.deps import DbSession, get_db
from app.models import Division
from app.rbac import check_admin_routes
from app.request_id import assign_request_id
from app.roll_signing import check_roll_at_startup
from app.routers import admin, auth, ballot, public, register
from app.schemas import DivisionOut


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # SR-11: first, and before any database work: without a usable ballot key no ballot could be
    # stored safely, so the API refuses to start rather than fall back to anything weaker
    check_ballot_key_at_startup()
    # SR-02: the API refuses to start unless every electoral roll record's signature checks out.
    # Uses the routes' database dependency, so tests check their own database.
    sessions = app.dependency_overrides.get(get_db, get_db)()
    try:
        db = next(sessions)
        check_roll_at_startup(db)
        # SR-07: and every election whose polls are not closed must have a valid signed definition
        check_definitions_at_startup(db)
    finally:
        sessions.close()
    yield


app = FastAPI(title="Electronic voting prototype API", version="0.1.0", lifespan=lifespan)

BALLOT_SUBMIT_PATH = "/api/ballot/submit"


@app.exception_handler(RequestValidationError)
async def validation_failed(request: Request, exc: RequestValidationError) -> Response:
    # SR-11: FastAPI's default 422 repeats the submitted input, which for a malformed ballot would
    # send the ranking back out. There only where and why it failed is kept; other routes are unchanged.
    if request.url.path == BALLOT_SUBMIT_PATH:
        errors = [{key: error[key] for key in ("type", "loc", "msg") if key in error} for error in exc.errors()]
        return JSONResponse({"detail": jsonable_encoder(errors)}, status_code=422)
    return await request_validation_exception_handler(request, exc)


# SR-16: declared first, so it is the innermost middleware: tls_required still refuses plaintext
# before anything runs, and no_store and HSTS still apply to every response it passes back.
# Every request handled here gets a fresh request id for its audit entries and X-Request-ID.
app.middleware("http")(assign_request_id)


@app.middleware("http")
async def no_store(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    # SR-09: no browser or proxy may keep a copy of any API response (ballots, receipts, errors).
    # Runs outside FastAPI's exception handlers, so 401, 404, 422, 429, 503 and redirects get it too.
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@app.middleware("http")
async def require_tls(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    # SR-10: declared after no_store, so it is the outermost middleware. A plaintext request is
    # refused before anything else runs (so a plain `uvicorn app.main:app` is no way around TLS),
    # and every HTTPS response, errors included, tells the browser to use HTTPS only.
    if request.url.scheme != "https":
        # SR-09 still applies: this refusal never reaches no_store, so it sets the headers itself
        return JSONResponse(
            {"detail": "tls_required"}, status_code=400, headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
        )
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = f"max-age={settings.hsts_max_age}"
    return response


app.include_router(auth.router, prefix="/api")
app.include_router(ballot.router, prefix="/api")
app.include_router(register.router, prefix="/api")
# SR-05: staff routes, all declared through AdminRouter
app.include_router(admin.router, prefix="/api")
# SR-18: open routes; only the published results key. It is outside /api/admin on purpose, so a
# recipient needs no account to fetch it
app.include_router(public.router, prefix="/api")


@app.get("/api/health", tags=["health"])
def health(db: DbSession) -> Response:
    """
    Liveness check. Reports status only, so it reveals nothing about the system.
    SR-19: the probe the availability monitor calls every 30 seconds. "ok" only if the database
    answers within 2 seconds and the required keys are loaded; otherwise 503. No session, no audit
    entry (one every 30 seconds would flood the SR-16 log) and no rate limit.
    """
    if app_health.database_answers(db) and app_health.required_keys_loaded():
        return JSONResponse({"status": "ok"})
    # SR-19: the same body whatever failed, so the probe tells an outsider nothing about the inside
    return JSONResponse({"status": "unavailable"}, status_code=503)


@app.get("/api/divisions", tags=["divisions"])
def list_divisions(db: DbSession) -> list[DivisionOut]:
    """Every electoral division, sorted by name."""
    return [DivisionOut.model_validate(d) for d in db.scalars(select(Division).order_by(Division.name))]


def serve_frontend(app: FastAPI, dist: Path) -> None:
    """
    SR-10: serves the built voter app and staff page through the same HTTPS entry point as the
    API. The files are the router's fallback, used only once no API route matched (and after
    FastAPI's trailing-slash redirect), so they can never shadow an API path. A mount at "/"
    would catch unknown /api paths first. Without a build (tests, CI) the API runs on its own.
    """
    if dist.is_dir():
        app.router.default = StaticFiles(directory=dist, html=True)


serve_frontend(app, PROJECT_DIR / "frontend" / "dist")


# SR-05: last, once every route exists. Refuses to start if any /api/admin route lacks a mapped
# permission. There is no setting to skip it.
check_admin_routes(app)
