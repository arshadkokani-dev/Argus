import re
from datetime import datetime
from urllib.parse import urlparse
from uuid import UUID
from pydantic import BaseModel, Field, field_validator

from app.models.target import VerificationMethod

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class TargetCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)
    verification_method: VerificationMethod = VerificationMethod.DNS_TXT

    @field_validator("domain")
    @classmethod
    def normalize_and_validate_domain(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            cleaned = parsed.hostname or ""
        else:
            cleaned = cleaned.split("/")[0].split(":")[0]

        if not DOMAIN_REGEX.match(cleaned):
            raise ValueError("Please provide a valid public domain name (e.g., example.com).")
        return cleaned


class TargetResponse(BaseModel):
    id: UUID
    domain: str
    base_url: str
    verification_token: str
    verification_method: VerificationMethod
    is_verified: bool
    created_at: datetime

    model_config = {"from_attributes": True}
