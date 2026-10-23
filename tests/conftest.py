"""Keep automated checks out of the user's local event history."""

import pytest

import security.logger as logger


@pytest.fixture(autouse=True)
def isolated_security_log(tmp_path, monkeypatch):
    directory = tmp_path / "security-logs"
    monkeypatch.setattr(logger, "LOG_DIR", directory)
    monkeypatch.setattr(logger, "LOG_FILE", directory / "security_events.jsonl")
