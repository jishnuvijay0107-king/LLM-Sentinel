from datetime import datetime
from pydantic import BaseModel, Field


class SecurityAnalysisRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="User input to analyze for potential prompt injection.",
    )


class ThreatDetectionResponse(BaseModel):
    category: str
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
    )
    reason: str


class SecurityAnalysisResponse(BaseModel):
    event_id: str = Field(
        ...,
        description="Unique identifier for the security analysis event.",
    )

    timestamp: datetime = Field(
        ...,
        description="UTC timestamp when the security event was created.",
    )

    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
    )

    risk_level: str

    decision: str

    detections: list[ThreatDetectionResponse]
