"""Local workbench data. Credentials and full prompts are never returned."""

import json
import os
from collections import Counter
from typing import Literal

from fastapi import APIRouter, Query, Request

import security.logger as audit
from backend.app.rate_limiter import limiter
from security.evaluator import evaluate_dataset

router = APIRouter(prefix="/api/v1/workspace", tags=["Workbench"])

FINDING_LABELS = {
    "instruction_manipulation": "Instruction override",
    "prompt_extraction": "Private prompt request",
    "role_manipulation": "Role change",
    "policy_bypass": "Safety bypass",
    "jailbreak": "Jailbreak instruction",
    "cyberattack_intent": "Network or account attack",
    "harmful_illegal_content": "Harmful request",
    "unicode_control_character": "Hidden text formatting",
    "base64_payload": "Disguised instruction",
    "financial_crime": "Fraud or theft request",
}


@router.get("/config")
def workspace_config():
    return {"providers": {
        name: bool(os.getenv(f"{name.upper()}_API_KEY"))
        for name in ("groq", "gemini", "openai")
    }}


@router.get("/events")
@limiter.limit("120/minute")
def workspace_events(
    request: Request,
    q: str = Query(default="", max_length=200),
    decision: Literal["ALL", "ALLOW", "REVIEW", "BLOCK"] = "ALL",
    limit: int = Query(default=30, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    events = []
    if audit.LOG_FILE.exists():
        with audit.LOG_FILE.open(encoding="utf-8") as source:
            for line in source:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue  # A concurrently appended or malformed line is skipped.
                if isinstance(event, dict) and event.get("event_id") and event.get("decision") in {"ALLOW", "REVIEW", "BLOCK"}:
                    # Return a fixed schema; do not leak future log fields by default.
                    events.append({key: event.get(key) for key in (
                        "event_id", "timestamp", "risk_score", "risk_level", "decision", "detections"
                    )})
    counts = Counter(e["decision"] for e in events)
    needle = q.casefold()
    filtered = [e for e in reversed(events)
                if (decision == "ALL" or e["decision"] == decision)
                and (not needle or needle in (e["event_id"] + " " + " ".join(
                    d.get("category", "") + " " + FINDING_LABELS.get(d.get("category"), "")
                    for d in (e.get("detections") or [])
                )).casefold())]
    return {
        "events": filtered[offset:offset + limit], "matched": len(filtered),
        "total": len(events), "counts": dict(counts),
        "has_more": offset + limit < len(filtered),
    }


@router.post("/evaluate")
@limiter.limit("10/minute")
def workspace_evaluate(request: Request):
    return evaluate_dataset()
