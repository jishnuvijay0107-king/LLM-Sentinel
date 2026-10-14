import base64
from dataclasses import dataclass
import re
import unicodedata


@dataclass
class ObfuscationDetection:
    category: str
    confidence: float
    reason: str


def detect_obfuscation(prompt: str) -> list[ObfuscationDetection]:
    detections = []

    for character in prompt:
        category = unicodedata.category(character)

        # Normal whitespace control characters are allowed.
        # Newline, carriage return and tab are common in
        # legitimate multi-line prompts.
        if character in {"\n", "\r", "\t"}:
            continue

        if category in {"Cf", "Cc"}:
            detections.append(
                ObfuscationDetection(
                    category="unicode_control_character",
                    confidence=0.85,
                    reason=(
                        f"Detected Unicode control/format character: "
                        f"U+{ord(character):04X}"
                    ),
                )
            )

    # Detect Base64 obfuscated attack payloads
    tokens = re.findall(r"[A-Za-z0-9+/]{12,}={0,2}", prompt)
    for token in tokens:
        try:
            decoded_bytes = base64.b64decode(token, validate=True)
            decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
            if len(decoded_text) >= 8 and any(c.isalpha() for c in decoded_text):
                from security.detector import detect_prompt_injection

                inner_threats = detect_prompt_injection(decoded_text)
                if inner_threats:
                    categories = ", ".join(t.category for t in inner_threats)
                    for sub_d in inner_threats:
                        detections.append(sub_d)
                    detections.append(
                        ObfuscationDetection(
                            category="base64_payload",
                            confidence=0.95,
                            reason=(
                                f"Decoded Base64 attack payload ({categories}): "
                                f"'{decoded_text}'"
                            ),
                        )
                    )
        except Exception:
            continue

    return detections