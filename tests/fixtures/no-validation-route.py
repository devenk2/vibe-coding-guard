# API route that writes directly to DB without input validation
# This should be caught by Vibe Coding Guard

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy.orm import Session

router = APIRouter()


class FlashcardIn(BaseModel):
    term: str
    definition: str
    domain: str


class Flashcard:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


@router.post("/flashcards/manual")
async def create_flashcard(data: FlashcardIn, db: Session):
    flashcard = Flashcard(**data.model_dump())
    db.add(flashcard)
    db.commit()
    return {"status": "created"}
