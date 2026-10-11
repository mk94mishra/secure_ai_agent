# policy/models.py

from typing import Literal, Optional

from pydantic import BaseModel, Field


class ActionRequest(BaseModel):
    incident_id: str
    tenant_id: str

    action: str
    resource_id: str

    risk_level: Literal["HIGH", "CRITICAL"]
    confidence: float = Field(ge=0.0, le=1.0)

    approval_status: Optional[str] = None
    approved_by: Optional[str] = None

    idempotency_key: str