"""Private notes API: each user sees and changes only their own notes."""

import uuid

from fastapi import APIRouter, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from swf import clock
from swf.deps import DB, ReadyUser
from swf.errors import AppError
from swf.models import User
from swf.security.vault import UserVault
from swf.services import audit

from notes_app.models import Note

router = APIRouter(prefix="/api/notes", tags=["notes"])
PURPOSE = "note"

NOTE_ADDED = "note_added"
NOTE_DELETED = "note_deleted"
AUDIT_LABELS = {NOTE_ADDED: "Note added", NOTE_DELETED: "Note deleted"}


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=10_000)


def _out(user: User, note: Note) -> dict:
    return {
        "id": str(note.id),
        "body": UserVault.for_user(user).open(note.body_enc, PURPOSE, str(note.id)).decode(),
        "created_at": note.created_at.isoformat(),
    }


@router.get("")
def list_notes(user: ReadyUser, db: DB) -> dict:
    # Always filter by the signed-in user: the framework never hands out another user's id.
    rows = db.scalars(select(Note).where(Note.user_id == user.id).order_by(Note.created_at.desc())).all()
    return {"items": [_out(user, n) for n in rows]}


@router.post("", status_code=201)
def add_note(body: NoteIn, user: ReadyUser, db: DB) -> dict:
    note_id = uuid.uuid4()
    note = Note(
        id=note_id,
        user_id=user.id,
        body_enc=UserVault.for_user(user).seal(body.body.encode(), PURPOSE, str(note_id)),
        created_at=clock.utcnow(),
        updated_at=clock.utcnow(),
    )
    db.add(note)
    audit.record(db, user, NOTE_ADDED)
    db.commit()
    return _out(user, note)


@router.delete("/{note_id}", status_code=204)
def delete_note(note_id: uuid.UUID, user: ReadyUser, db: DB) -> Response:
    note = db.scalar(select(Note).where(Note.id == note_id, Note.user_id == user.id))
    if note is None:
        raise AppError(404, "note_not_found", "That note doesn't exist any more. Reload the page.")
    db.delete(note)
    audit.record(db, user, NOTE_DELETED)
    db.commit()
    return Response(status_code=204)
