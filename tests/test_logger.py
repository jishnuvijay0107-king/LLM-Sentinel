import json
from uuid import UUID

import security.logger as logger


def test_log_security_event(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_file = log_dir / "security_events.jsonl"

    monkeypatch.setattr(logger, "LOG_DIR", log_dir)
    monkeypatch.setattr(logger, "LOG_FILE", log_file)

    detections = [
        {
            "category": "instruction_manipulation",
            "confidence": 0.9,
            "reason": "Detected suspicious pattern",
        }
    ]

    event = logger.log_security_event(
        risk_score=90,
        risk_level="CRITICAL",
        decision="BLOCK",
        detections=detections,
    )

    assert log_file.exists()

    lines = log_file.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 1

    stored_event = json.loads(lines[0])

    assert stored_event["event_id"] == event["event_id"]
    assert stored_event["risk_score"] == 90
    assert stored_event["risk_level"] == "CRITICAL"
    assert stored_event["decision"] == "BLOCK"
    assert stored_event["detections"] == detections
    assert "timestamp" in stored_event

    # Verify event_id is a valid UUID.
    UUID(stored_event["event_id"])


def test_security_event_ids_are_unique(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_file = log_dir / "security_events.jsonl"

    monkeypatch.setattr(logger, "LOG_DIR", log_dir)
    monkeypatch.setattr(logger, "LOG_FILE", log_file)

    event_one = logger.log_security_event(
        risk_score=10,
        risk_level="LOW",
        decision="ALLOW",
        detections=[],
    )

    event_two = logger.log_security_event(
        risk_score=90,
        risk_level="CRITICAL",
        decision="BLOCK",
        detections=[],
    )

    assert event_one["event_id"] != event_two["event_id"]
