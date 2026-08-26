import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "security_events.jsonl"


def log_security_event(
    *,
    risk_score: int,
    risk_level: str,
    decision: str,
    detections: list,
) -> dict:
    """
    Store a security analysis event in JSON Lines format.

    Each event receives:
    - a unique event_id
    - a UTC timestamp
    - risk information
    - security detections

    Returns the complete event that was written to the audit log.
    """

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    event = {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "decision": decision,
        "detections": detections,
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")

    return event