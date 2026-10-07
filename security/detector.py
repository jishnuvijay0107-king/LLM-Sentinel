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
    Detect common prompt-injection and instruction-manipulation
    patterns.
    """

    detections: list[ThreatDetection] = []

    text = _normalize_for_detection(prompt)

    patterns = {
        "instruction_manipulation": [
            r"\bignore\s+(all\s+)?previous\s+instructions\b",
            r"\bignore\s+(the\s+)?previous\s+instructions\b",

            r"\bdisregard\s+(all\s+)?previous\s+instructions\b",
            r"\bdisregard\s+(the\s+)?previous\s+instructions\b",
            r"\bdisregard\s+(the\s+)?instructions\s+(above|earlier)\b",

            r"\bdisregard\s+(what\s+you\s+were\s+told)\s+(previously|earlier)\b",

            r"\bdisregard\s+(the\s+)?instructions\s+(you\s+received)\s+(earlier|previously)\b",

            r"\bforget\s+(all\s+)?previous\s+instructions\b",
            r"\bforget\s+(the\s+)?instructions\s+(above|earlier)\b",

            r"\boverride\s+(the\s+)?previous\s+instructions\b",

            r"\breplace\s+(the\s+)?instructions\s+(above|earlier)\b",

            r"\bnew\s+instructions\s*:",

            r"\bfrom\s+now\s+on\s*,?\s+(ignore|disregard)\b",

            r"\bfrom\s+now\s+on\s*,?\s+follow\s+(these|the)\s+new\s+instructions\b",
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
            r"\byou\s+are\s+now\s+operating\b",
            r"\boperating\s+under\s+(a\s+)?(different|new)\b",

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

        "jailbreak": [
            r"\b(dan|do\s+anything\s+now)\b",
            r"\bdeveloper\s+mode\b",
            r"\bjailbreak\b",
            r"\bdisable\s+all\s+(moral|ethical)\s+guidelines\b",
        ],

        "cyberattack_intent": [
            r"\b(hack|crack|breach|infiltrate|penetrate)\s+([a-z0-9_-]+\s+)?(wifi|network|router|wpa|wpa2|wpa3|handshake|server|database|system|account|credentials?|password)\b",
            r"\b(hack|crack|compromise|exploit|infiltrate)\s+(into\s+)?([a-z0-9_-]+\s+)?(wifi|network|database|server|system|account|credentials?|portal)\b",
            r"\b(i\s+need\s+to\s+|i\s+need\s+|how\s+to\s+|help\s+me\s+)(hack|crack|breach|exploit|infiltrate|ddos|phish)\b",
            r"\b(steal|dump|harvest|sniff)\s+(passwords?|credentials?|wifi\s+passwords?|hashes|tokens?|keys?)\b",
            r"\b(create|write|generate|build)\s+(a\s+)?(keylogger|ransomware|trojan|malware|botnet|ddos\s+tool|exploit\s+payload)\b",
            r"\b(bypass|crack)\s+(wifi\s+password|wpa2\s+password|network\s+authentication)\b",
        ],
    }

    confidence_by_category = {
        "instruction_manipulation": 0.90,
        "prompt_extraction": 0.90,
        "role_manipulation": 0.85,
        "policy_bypass": 0.90,
        "jailbreak": 0.95,
        "cyberattack_intent": 0.95,
    }

    for category, category_patterns in patterns.items():

        match = _find_pattern(
            text,
            category_patterns,
        )

        if match:

            # Avoid false positives when discussing educational cybersecurity defense
            if (
                category == "cyberattack_intent"
                and (
                    "protect" in text
                    or "prevent" in text
                    or "defend" in text
                    or "ethical" in text
                )
            ):
                continue

            # Avoid false positives when a document is merely
            # discussing previous instructions.
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
                    reason=(
                        f"Detected suspicious pattern: {match}"
                    ),
                )
            )

    return detections