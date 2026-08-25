from dataclasses import dataclass
import unicodedata


@dataclass
class ObfuscationDetection:
    category: str
    confidence: float
    reason: str


def detect_obfuscation(prompt: str) -> list[ObfuscationDetection]:
    """
    Detect suspicious character-level obfuscation techniques.
    """

    detections: list[ObfuscationDetection] = []

    for character in prompt:
        category = unicodedata.category(character)

        # Detect Unicode control/format characters.
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

    return detections