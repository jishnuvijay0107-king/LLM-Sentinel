from fastapi import APIRouter

from backend.app.models import (
    SecurityAnalysisRequest,
    SecurityAnalysisResponse,
)

from security.normalizer import normalize_text
from security.detector import detect_prompt_injection
from security.obfuscation_detector import detect_obfuscation
from security.risk_engine import calculate_risk, get_risk_level
from security.policy_engine import make_decision
from security.logger import log_security_event


router = APIRouter(
    prefix="/api/v1/security",
    tags=["Security Analysis"],
)


@router.post(
    "/analyze",
    response_model=SecurityAnalysisResponse,
)
def analyze_prompt(request: SecurityAnalysisRequest):
    """
    Analyze user input for prompt injection
    and character-level obfuscation.
    """

    # Keep the original prompt for obfuscation detection.
    original_prompt = request.prompt

    # Normalize only for semantic prompt-injection detection.
    normalized_prompt = normalize_text(original_prompt)

    # 1. Detect prompt injection on normalized text
    injection_detections = detect_prompt_injection(
        normalized_prompt
    )

    # 2. Detect obfuscation on ORIGINAL text
    obfuscation_detections = detect_obfuscation(
        original_prompt
    )

    # 3. Combine all detections
    detections = (
        injection_detections
        + obfuscation_detections
    )

    # 4. Calculate risk score
    risk_score = calculate_risk(detections)

    # 5. Determine risk level
    risk_level = get_risk_level(risk_score)

    # 6. Make security decision
    decision = make_decision(risk_score)

    # 7. Convert detections to API format
    response_detections = [
        {
            "category": detection.category,
            "confidence": detection.confidence,
            "reason": detection.reason,
        }
        for detection in detections
    ]

    # 8. Write security audit event
    event = log_security_event(
        risk_score=risk_score,
        risk_level=risk_level,
        decision=decision,
        detections=response_detections,
    )

    # 9. Return security analysis response
    return SecurityAnalysisResponse(
        event_id=event["event_id"],
        timestamp=event["timestamp"],
        risk_score=risk_score,
        risk_level=risk_level,
        decision=decision,
        detections=response_detections,
    )