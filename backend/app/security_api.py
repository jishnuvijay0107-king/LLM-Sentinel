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

    # 1. Normalize input
    normalized_prompt = normalize_text(request.prompt)

    # 2. Detect prompt injection
    injection_detections = detect_prompt_injection(
        normalized_prompt
    )

    # 3. Detect obfuscation
    obfuscation_detections = detect_obfuscation(
        normalized_prompt
    )

    # 4. Combine all detections
    detections = (
        injection_detections
        + obfuscation_detections
    )

    # 5. Calculate risk score
    risk_score = calculate_risk(detections)

    # 6. Determine risk level
    risk_level = get_risk_level(risk_score)

    # 7. Make security decision
    decision = make_decision(risk_score)

    # 8. Convert detections to API format
    response_detections = [
        {
            "category": detection.category,
            "confidence": detection.confidence,
            "reason": detection.reason,
        }
        for detection in detections
    ]

    # 9. Write security audit event
    log_security_event(
        risk_score=risk_score,
        risk_level=risk_level,
        decision=decision,
        detections=response_detections,
    )

    # 10. Return API response
    return SecurityAnalysisResponse(
        risk_score=risk_score,
        risk_level=risk_level,
        decision=decision,
        detections=response_detections,
    )