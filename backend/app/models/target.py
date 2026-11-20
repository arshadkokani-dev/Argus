import enum
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID

from app.db.session import Base


class VerificationMethod(str, enum.Enum):
    DNS_TXT = "DNS_TXT"
    WELL_KNOWN_FILE = "WELL_KNOWN_FILE"


def generate_verification_token() -> str:
    return f"argus-verify={secrets.token_hex(16)}"


class Target(Base):
    __tablename__ = "targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    domain = Column(String(255), nullable=False, index=True)
    base_url = Column(String(512), nullable=False)
    verification_token = Column(
        String(128), default=generate_verification_token, nullable=False
    )
    verification_method = Column(
        Enum(VerificationMethod), default=VerificationMethod.DNS_TXT, nullable=False
    )
    is_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
