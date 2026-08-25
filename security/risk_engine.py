from security.detector import ThreatDetection
from security.obfuscation_detector import ObfuscationDetection


# Both detector result types are accepted by the risk engine.
Detection = ThreatDetection | ObfuscationDetection


# Risk contribution of each detection category.
CATEGORY_WEIGHTS = {
    "instruction_manipulation": 35,
    "prompt_extraction": 30,
    "role_manipulation": 25,
    "unicode_control_character": 30,
}


# Categories considered especially dangerous.
HIGH_RISK_CATEGORIES = {
    "instruction_manipulation",
    "prompt_extraction",
}


def calculate_risk(detections: list[Detection]) -> int:
    """
    Calculate a 0-100 security risk score.

    Risk is based on:
    - detection category
    - detector confidence
    - multiple independent attack signals
    """

    if not detections:
        return 0

    score = 0.0

    for detection in detections:
        weight = CATEGORY_WEIGHTS.get(
            detection.category,
            15,
        )

        score += weight * detection.confidence

    # Multiple high-risk categories indicate
    # a stronger prompt-injection attempt.
    high_risk_count = sum(
        1
        for detection in detections
        if detection.category in HIGH_RISK_CATEGORIES
    )

    if high_risk_count >= 2:
        score += 30

    return min(int(score), 100)


def get_risk_level(score: int) -> str:
    """
    Convert numerical risk score into a severity level.
    """

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"