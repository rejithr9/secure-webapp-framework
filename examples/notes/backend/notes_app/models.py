"""The example app's own table. Note how it plugs into the framework's rules:

- it subclasses `swf.db.Base`,
- it references `users.id` with ON DELETE CASCADE, so account deletion and the retention
  purge remove a user's notes automatically,
- the note text is encrypted with the owner's personal data key (`UserVault`).
"""

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, LargeBinary, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from swf import clock
from swf.db import Base, UTCDateTime


def _now() -> datetime:
    return clock.utcnow()


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    body_enc: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
