def make_decision(risk_score: int) -> str:
    """
    Convert a risk score into a security decision.

    Risk policy:
        0-29   -> ALLOW
        30-59  -> REVIEW
        60-79  -> BLOCK
        80-100 -> BLOCK
    """

    if risk_score >= 60:
        return "BLOCK"

    if risk_score >= 30:
        return "REVIEW"

    return "ALLOW"