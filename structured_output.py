from pydantic import BaseModel, Field
from typing import Literal


class SecurityAnalysis(BaseModel):

    severity: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    confidence: float = Field(
        ge=0,
        le=1
    )

    summary: str

    recommended_action: str