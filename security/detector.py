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
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(0)

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
            r"\bignore\s+(all\s+)?previous\s+rules\b",
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
            r"\b(output|repeat|copy)\s+(the\s+)?(initial|system)\s+instructions\b",
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

            r"\b(act|pretend|roleplay)\s+(as|you\s+are)\s+(a|an|the\s+)?(system\s+)?(admin|administrator|root|developer)\b",
        ],

        "policy_bypass": [
            r"\bbypass\s+(your\s+)?safety\s+(rules|policies|filters)\b",

            r"\bdisable\s+(your\s+)?safety\s+(rules|policies|filters)\b",

            r"\bignore\s+(your\s+)?safety\s+(rules|policies|filters)\b",

            r"\bdisregard\s+(your\s+)?safety\s+(rules|policies|filters)\b",

            r"\bdisable\s+your\s+restrictions\b",

            r"\bremove\s+your\s+restrictions\b",

            r"\bignore\s+your\s+content\s+policy\b",

            r"\bdo\s+not\s+follow\s+(your\s+)?safety\s+rules\b",
        ],

        "jailbreak": [
            r"\b(act\s+as|you\s+are\s+(now\s+)?|become|enable)\s*dan\b",
            r"\bdo\s+anything\s+now\b",
            r"\bdeveloper\s+mode\b",
            r"\bjailbreak\b",
            r"\bdisable\s+all\s+(moral|ethical)\s+guidelines\b",
        ],

        "cyberattack_intent": [
            # Short, direct requests must work without a "how to" prefix.
            # Keep explicit targets so ordinary account-security questions do not match.
            r"\b(hack|crack|compromise|breach|break\s+into)\s+(into\s+)?(?:(?:my|your|the|a|an|someone['’]?s|anyone['’]?s|friend['’]?s)\s+){0,3}(insta(?:gram)?|facebook|fb|whatsapp|snapchat|gmail|tiktok|telegram|twitter|social\s+media)(\s+account)?\b",
            r"\b(hack|compromise|take\s+over)\s+(you|chatgpt|this\s+(ai|assistant|chatbot))\b",
            r"\b(hack|crack|breach)\s+(?:(?:the|a|an|my|your|srm|college|school|campus|neighbou?r['’]?s)\s+){0,3}(wi[\s-]?fi|wireless\s+network)\b",
            r"\b(hack|crack|breach|infiltrate|penetrate)\s+([a-z0-9_-]+\s+)?(wifi|network|router|wpa|wpa2|wpa3|handshake|server|database|system|account|credentials?|password)\b",
            r"\b(hack|crack|compromise|exploit|infiltrate)\s+(into\s+)?([a-z0-9_-]+\s+)?(wifi|network|database|server|system|account|credentials?|portal)\b",
            r"\b(i\s+need\s+to\s+|i\s+need\s+|how\s+to\s+|help\s+me\s+)(hack|crack|breach|exploit|infiltrate|ddos|phish)\b",
            r"\b(steal|dump|harvest|sniff)\s+(passwords?|credentials?|wifi\s+passwords?|hashes|tokens?|keys?)\b",
            r"\b(create|write|generate|build)\s+(a\s+)?(keylogger|ransomware|trojan|malware|botnet|ddos\s+tool|exploit\s+payload)\b",
            r"\b(bypass|crack)\s+(wifi\s+password|wpa2\s+password|network\s+authentication)\b",
        ],

        "harmful_illegal_content": [
            r"\b(kill|murder|poison|stab|torture|kidnap)\s+(?:(?:my|your|his|her|the|a|an)\s+)?(neighbou?r|friend|enemy|teacher|boss|partner|wife|husband|child|father|mother|brother|sister|him|her|them)\b",
            r"\b(how\s+to\s+)?(make|build|create|manufacture|assemble|synthesize|cook|prepare)\s+(a\s+)?(bomb|explosive|pipe\s*bomb|ied|molotov|dynamite|c4|grenade|boob\b|detonator|suicide\s*vest|landmine)\b",
            r"\b(how\s+to\s+)?(make|build|construct|manufacture)\s+(a\s+)?(gun|firearm|ghost\s*gun|weapon|biological\s*weapon|chemical\s*weapon|dirty\s*bomb)\b",
            r"\b(recipe|instructions|guide|formula)\s+(for|to\s+make)\s+(a\s+)?(bomb|explosive|pipe\s*bomb|ied|molotov|poison|ricin|cyanide)\b",
            r"\b(synthesize|manufacture)\s+(ricin|anthrax|sarin|cyanide|mustard\s*gas|vx\s*nerve\s*agent)\b",
            r"\b(how\s+to\s+)?(kill|murder|assassinate|strangle|poison|slaughter|stab|execute|harm|torture)\s+(a\s+|the\s+)?(person|preson\b|someone|human|individual|people|man|woman|child|body)\b",
            r"\b(kill|murder|assassinate|poison)\s+(a\s+|the\s+)?(person|preson\b|someone|human|individual)\b",
            r"\bhow\s+to\s+(hire|find)\s+(a\s+)?(hitman|contract\s*killer|assassin)\b",
            r"\bways\s+to\s+(kill|murder)\s+(someone|a\s+person|people)\b",
            r"\bhow\s+to\s+get\s+away\s+with\s+(murder|killing)\b",
        ],

        "financial_crime": [
            r"\b(rob|burgle)\s+(a|the|my|your)\s+(bank|house|store|shop)\b",
            r"\b(steal|launder)\s+(?:someone['’]?s\s+|other\s+people['’]?s\s+)?(money|credit\s+cards?|bank\s+details)\b",
            r"\b(how\s+to|help\s+me|i\s+(?:want|need)\s+to)\s+(?:commit\s+fraud|forge\s+(?:a\s+)?signature|make\s+(?:a\s+)?fake\s+passport)\b",
        ],
    }

    confidence_by_category = {
        "instruction_manipulation": 0.90,
        "prompt_extraction": 0.90,
        "role_manipulation": 0.85,
        "policy_bypass": 0.90,
        "jailbreak": 0.95,
        "cyberattack_intent": 0.95,
        "harmful_illegal_content": 0.95,
        "financial_crime": 0.95,
    }

    for category, category_patterns in patterns.items():

        match = _find_pattern(
            text,
            category_patterns,
        )

        if match:

            # A complete, bounded reference to outdated document instructions.
            # A phrase elsewhere in an attack must never disable a category.
            if (
                category == "instruction_manipulation"
                and re.fullmatch(
                    r"(?:this|the) (?:article|document) explains why you should "
                    r"ignore previous instructions from an outdated document\.?",
                    text,
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
