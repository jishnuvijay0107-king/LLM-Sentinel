import json
from datetime import datetime, timezone
from pathlib import Path


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "security_events.jsonl"


def log_security_event(
    *,
    risk_score: int,
    risk_level: str,
    decision: str,
    detections: list,
) -> None:
    """
    Store a security analysis event in JSON Lines format.
    """

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "decision": decision,
        "detections": detections,
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")