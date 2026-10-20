"""FastAPI application. Every route lives under /api, matching the frontend's dev proxy."""

from fastapi import FastAPI

from app.routers import auth, ballot, divisions, health

app = FastAPI(title="Electronic voting prototype API", version="0.1.0")

app.include_router(health.router, prefix="/api")
app.include_router(divisions.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
app.include_router(ballot.router, prefix="/api")
