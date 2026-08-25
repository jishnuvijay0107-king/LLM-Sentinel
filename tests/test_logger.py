import json

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

    logger.log_security_event(
        risk_score=90,
        risk_level="CRITICAL",
        decision="BLOCK",
        detections=detections,
    )

    assert log_file.exists()

    lines = log_file.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 1

    event = json.loads(lines[0])

    assert event["risk_score"] == 90
    assert event["risk_level"] == "CRITICAL"
    assert event["decision"] == "BLOCK"
    assert event["detections"] == detections
    assert "timestamp" in event