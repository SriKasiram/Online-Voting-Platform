from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness check. Reports status only, so it reveals nothing about the system."""
    return {"status": "ok"}
