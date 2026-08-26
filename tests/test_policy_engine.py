from security.obfuscation_detector import ObfuscationDetection
from security.policy_engine import make_decision
from security.risk_engine import calculate_risk, get_risk_level


def test_low_risk_allows():
    score = 10

    assert get_risk_level(score) == "LOW"
    assert make_decision(score) == "ALLOW"


def test_medium_risk_requires_review():
    score = 40

    assert get_risk_level(score) == "MEDIUM"
    assert make_decision(score) == "REVIEW"


def test_high_risk_blocks():
    score = 60

    assert get_risk_level(score) == "HIGH"
    assert make_decision(score) == "BLOCK"


def test_critical_risk_blocks():
    score = 80

    assert get_risk_level(score) == "CRITICAL"
    assert make_decision(score) == "BLOCK"


def test_unicode_obfuscation_requires_review():
    detection = ObfuscationDetection(
        category="unicode_control_character",
        confidence=0.85,
        reason="Detected Unicode control/format character: U+200B",
    )

    score = calculate_risk([detection])

    assert score >= 30
    assert get_risk_level(score) == "MEDIUM"
    assert make_decision(score) == "REVIEW"