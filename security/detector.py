from dataclasses import dataclass


@dataclass
class ThreatDetection:
    category: str
    confidence: float
    reason: str


def _contains_any(text: str, patterns: list[str]) -> str | None:
    """Return the first matching pattern."""

    for pattern in patterns:
        if pattern in text:
            return pattern

    return None


def detect_prompt_injection(prompt: str) -> list[ThreatDetection]:
    """
    Detect potential prompt injection patterns.

    Detection categories:
    - instruction manipulation
    - prompt extraction
    - role manipulation

    This is the rule-based detection layer.
    """

    detections: list[ThreatDetection] = []

    text = " ".join(prompt.lower().split())

    patterns = {
        "instruction_manipulation": [
            "ignore previous instructions",
            "ignore all previous instructions",
            "ignore the previous instructions",
            "disregard previous instructions",
            "disregard the previous instructions",
            "disregard the instructions above",
            "forget previous instructions",
            "forget the instructions above",
            "override previous instructions",
            "replace the instructions above",
        ],

        "prompt_extraction": [
            "reveal your system prompt",
            "reveal the system prompt",
            "reveal the system instructions",
            "show your system prompt",
            "show the system prompt",
            "show your system instructions",
            "tell me your system prompt",
            "tell me the system prompt",
            "hidden instructions",
            "hidden system instructions",
            "instructions controlling your behavior",
        ],

        "role_manipulation": [
            "you are now",
            "you are operating as",
            "act as system",
            "act as the system",
            "pretend you are the system",
            "operate as the system",
        ],
    }

    for category, keywords in patterns.items():

        match = _contains_any(text, keywords)

        if match:
            detections.append(
                ThreatDetection(
                    category=category,
                    confidence=0.90,
                    reason=f"Detected suspicious pattern: {match}",
                )
            )

    return detections