import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, String
from sqlalchemy.dialects.postgresql import UUID

from app.db.session import Base


class PlanTier(str, enum.Enum):
    FREE = "FREE"
    PRO = "PRO"
    AGENCY = "AGENCY"


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    plan_tier = Column(Enum(PlanTier), default=PlanTier.FREE, nullable=False)
    razorpay_customer_id = Column(String(255), nullable=True)
    subscription_status = Column(String(50), default="active", nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
