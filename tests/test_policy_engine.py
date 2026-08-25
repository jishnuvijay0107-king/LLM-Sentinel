from security.policy_engine import make_decision


def test_low_risk_allows():
    assert make_decision(0) == "ALLOW"
    assert make_decision(29) == "ALLOW"


def test_medium_risk_requires_review():
    assert make_decision(30) == "REVIEW"
    assert make_decision(59) == "REVIEW"


def test_high_risk_blocks():
    assert make_decision(60) == "BLOCK"
    assert make_decision(79) == "BLOCK"


def test_critical_risk_blocks():
    assert make_decision(80) == "BLOCK"
    assert make_decision(100) == "BLOCK"