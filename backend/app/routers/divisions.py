from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from app.database import DbSession
from app.models import Division

router = APIRouter(tags=["divisions"])


class DivisionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


@router.get("/divisions")
def list_divisions(db: DbSession) -> list[DivisionOut]:
    """Every electoral division, sorted by name. Proves the API can read the database."""
    divisions = db.scalars(select(Division).order_by(Division.name))
    return [DivisionOut.model_validate(division) for division in divisions]
