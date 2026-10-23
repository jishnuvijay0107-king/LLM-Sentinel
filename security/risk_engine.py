from security.detector import ThreatDetection
from security.obfuscation_detector import ObfuscationDetection


Detection = ThreatDetection | ObfuscationDetection


CATEGORY_WEIGHTS = {
    "instruction_manipulation": 35,
    "prompt_extraction": 30,
    "role_manipulation": 25,
    "policy_bypass": 35,
    "jailbreak": 70,
    "cyberattack_intent": 75,
    "harmful_illegal_content": 90,
    "financial_crime": 75,
    "unicode_control_character": 40,
    "base64_payload": 35,
}


HIGH_RISK_CATEGORIES = {
    "instruction_manipulation",
    "prompt_extraction",
    "policy_bypass",
    "jailbreak",
    "cyberattack_intent",
    "harmful_illegal_content",
    "financial_crime",
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

    # Repeated characters or the same rule in an encoded and plain payload
    # are one signal, rather than independent evidence.
    by_category = {}
    for detection in detections:
        previous = by_category.get(detection.category)
        if previous is None or detection.confidence > previous.confidence:
            by_category[detection.category] = detection

    detections = list(by_category.values())
    score = 0.0

    for detection in detections:
        weight = CATEGORY_WEIGHTS.get(
            detection.category,
            15,
        )

        score += weight * detection.confidence

    high_risk_count = sum(
        1
        for detection in detections
        if detection.category in HIGH_RISK_CATEGORIES
    )

    if high_risk_count >= 2:
        score += 30

    # A clear extraction/override must not be allowed just because it is the
    # only signal. Lower-confidence evidence remains subject to review.
    if any(d.category in HIGH_RISK_CATEGORIES and d.confidence >= 0.85 for d in detections):
        score = max(score, 60)
    elif detections:
        score = max(score, 30)

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
