from dataclasses import dataclass
import re


@dataclass
class ThreatDetection:
    category: str
    confidence: float
    reason: str


def _normalize_for_detection(text: str) -> str:
    """
    Normalize text for rule-based security detection.

    This is intentionally lightweight. Full Unicode normalization
    is handled by the normalizer layer.
    """
    return " ".join(text.lower().split())


def _find_pattern(text: str, patterns: list[str]) -> str | None:
    """
    Return the first matching security pattern.
    """

    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return pattern

    return None


def detect_prompt_injection(prompt: str) -> list[ThreatDetection]:
    """
    Detect common prompt-injection and instruction-manipulation patterns.

    Detection categories:
    - instruction manipulation
    - prompt extraction
    - role manipulation
    - policy bypass

    This is a deterministic rule-based detection layer.
    """

    detections: list[ThreatDetection] = []

    text = _normalize_for_detection(prompt)

    patterns = {
        "instruction_manipulation": [
            r"\bignore\s+(all\s+)?previous\s+instructions\b",
            r"\bignore\s+(the\s+)?previous\s+instructions\b",
            r"\bdisregard\s+(all\s+)?previous\s+instructions\b",
            r"\bdisregard\s+(the\s+)?instructions\s+(above|earlier)\b",
            r"\bforget\s+(all\s+)?previous\s+instructions\b",
            r"\bforget\s+(the\s+)?instructions\s+(above|earlier)\b",
            r"\boverride\s+(the\s+)?previous\s+instructions\b",
            r"\breplace\s+(the\s+)?instructions\s+(above|earlier)\b",
            r"\bnew\s+instructions\s*:",
            r"\bfrom\s+now\s+on\s*,?\s+ignore\b",
        ],

        "prompt_extraction": [
            r"\breveal\s+(your\s+|the\s+)?system\s+prompt\b",
            r"\breveal\s+(your\s+|the\s+)?system\s+instructions\b",
            r"\bshow\s+(your\s+|the\s+)?system\s+prompt\b",
            r"\bshow\s+(your\s+|the\s+)?system\s+instructions\b",
            r"\btell\s+me\s+(your\s+|the\s+)?system\s+prompt\b",
            r"\bprint\s+(your\s+|the\s+)?system\s+prompt\b",
            r"\bdisplay\s+(your\s+|the\s+)?system\s+prompt\b",
            r"\bwhat\s+are\s+your\s+hidden\s+instructions\b",
            r"\bhidden\s+(system\s+)?instructions\b",
            r"\binstructions\s+controlling\s+your\s+behavior\b",
        ],

        "role_manipulation": [
            r"\byou\s+are\s+now\s+(a|an|the)\b",
            r"\byou\s+are\s+operating\s+as\b",
            r"\bact\s+as\s+(a|an|the)?\s*system\b",
            r"\bpretend\s+you\s+are\s+(a|an|the)?\s*system\b",
            r"\boperate\s+as\s+(a|an|the)?\s*system\b",
            r"\broleplay\s+as\s+(a|an|the)?\s*system\b",
        ],

        "policy_bypass": [
            r"\bbypass\s+(your\s+)?safety\s+(rules|policies|filters)\b",
            r"\bdisable\s+(your\s+)?safety\s+(rules|policies|filters)\b",
            r"\bignore\s+(your\s+)?safety\s+(rules|policies|filters)\b",
            r"\bdisable\s+your\s+restrictions\b",
            r"\bremove\s+your\s+restrictions\b",
            r"\bignore\s+your\s+content\s+policy\b",
            r"\bdo\s+not\s+follow\s+(your\s+)?safety\s+rules\b",
        ],
    }

    confidence_by_category = {
        "instruction_manipulation": 0.90,
        "prompt_extraction": 0.90,
        "role_manipulation": 0.85,
        "policy_bypass": 0.90,
    }

    for category, category_patterns in patterns.items():
        match = _find_pattern(
            text,
            category_patterns,
        )

        if match:
            # Avoid treating clearly descriptive/documentation
            # language as an active instruction.
            if (
                category == "instruction_manipulation"
                and (
                    "this article explains" in text
                    or "this document explains" in text
                    or "the article explains" in text
                    or "the document explains" in text
                )
            ):
                continue

            detections.append(
                ThreatDetection(
                    category=category,
                    confidence=confidence_by_category[category],
                    reason=f"Detected suspicious pattern: {match}",
                )
            )

    return detections