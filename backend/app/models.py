from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class SecurityAnalysisRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description=(
            "User input to analyze for potential prompt injection."
        ),
    )

    model_config = {
        "extra": "forbid",
    }

    @field_validator("prompt")
    @classmethod
    def validate_prompt(cls, value: str) -> str:
        """
        Validate that the prompt contains meaningful input.
        """

        if not value.strip():
            raise ValueError(
                "Prompt cannot contain only whitespace."
            )

        return value


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
        description=(
            "Unique identifier for the security analysis event."
        ),
    )

    timestamp: datetime = Field(
        ...,
        description=(
            "UTC timestamp when the security event was created."
        ),
    )

    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
    )

    risk_level: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]

    decision: Literal[
        "ALLOW",
        "REVIEW",
        "BLOCK",
    ]

    detections: list[ThreatDetectionResponse]
    latency_ms: float = Field(
        default=0.0,
        description="Analysis latency in milliseconds.",
    )


class GuardedChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10000)
    provider: str = Field(default="builtin")
    api_key: str | None = Field(default=None)
    model: str | None = Field(default=None)


class GuardedChatResponse(BaseModel):
    event_id: str
    allowed: bool
    decision: Literal["ALLOW", "REVIEW", "BLOCK"]
    risk_score: int
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    detections: list[ThreatDetectionResponse]
    ai_response: str
    latency_ms: float