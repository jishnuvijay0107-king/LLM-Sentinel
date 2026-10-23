from dataclasses import dataclass
import unicodedata


@dataclass
class NormalizedInput:
    """
    Represents the result of security input normalization.

    original:
        The exact input received from the user.

    normalized:
        Canonical representation used by security detectors.

    changed:
        Indicates whether normalization changed the representation.
    """

    original: str
    normalized: str
    changed: bool


def normalize_text(text: str) -> str:
    """
    Normalize user input before security analysis.

    This function preserves the original input separately
    for auditing and forensic analysis.
    """

    normalized = unicodedata.normalize("NFKC", text)

    # Format characters must not split keywords during inspection. Keep the
    # original for the separate obfuscation detector and provider request.
    normalized = "".join(
        char for char in normalized
        if unicodedata.category(char) not in {"Cf", "Cc"}
        or char in "\n\r\t"
    )

    # Normalize line endings.
    normalized = normalized.replace("\r\n", "\n")
    normalized = normalized.replace("\r", "\n")

    # Normalize whitespace without changing the original input.
    normalized = " ".join(normalized.split())

    return normalized


def normalize_input(text: str) -> NormalizedInput:
    """
    Create a structured normalized representation of user input.
    """

    normalized = normalize_text(text)

    return NormalizedInput(
        original=text,
        normalized=normalized,
        changed=(text != normalized),
    )
