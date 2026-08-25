from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path


@dataclass
class AuditEvent:
    timestamp: str
    risk_score: int
    risk_level: str
    decision: str
    detection_count: int


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "security_audit.jsonl"


def log_security_event(
    risk_score: int,
    risk_level: str,
    decision: str,
    detection_count: int,
) -> None:
    """
    Store a security analysis event for auditing.
    """

    LOG_DIR.mkdir(exist_ok=True)

    event = AuditEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        risk_score=risk_score,
        risk_level=risk_level,
        decision=decision,
        detection_count=detection_count,
    )

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(
            json.dumps(event.__dict__) + "\n"
        )