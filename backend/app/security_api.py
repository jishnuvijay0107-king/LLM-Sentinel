import time

from fastapi import APIRouter, Request

from backend.app.models import (
    GuardedChatRequest, GuardedChatResponse,
    SecurityAnalysisRequest, SecurityAnalysisResponse,
)
from backend.app.rate_limiter import limiter
from backend.app.llm_client import generate_llm_response
from security.inspection import inspect_prompt, withheld_response
from security.logger import log_security_event

router = APIRouter(prefix="/api/v1/security", tags=["Security Analysis"])


def inspect_and_log(prompt: str) -> dict:
    result = inspect_prompt(prompt)
    event = log_security_event(
        risk_score=result["risk_score"], risk_level=result["risk_level"],
        decision=result["decision"], detections=result["detections"],
    )
    return {**result, "event_id": event["event_id"], "timestamp": event["timestamp"]}


@router.post("/analyze", response_model=SecurityAnalysisResponse)
@limiter.limit("1200/minute")
def analyze_prompt(request: Request, analysis_request: SecurityAnalysisRequest):
    return inspect_and_log(analysis_request.prompt)


@router.post("/chat", response_model=GuardedChatResponse)
@limiter.limit("300/minute")
def guarded_chat(request: Request, chat_request: GuardedChatRequest):
    start = time.perf_counter()
    result = inspect_and_log(chat_request.prompt)
    allowed = result["decision"] == "ALLOW"
    if allowed:
        answer = generate_llm_response(
            prompt=chat_request.prompt, provider=chat_request.provider,
            api_key=chat_request.api_key, model=chat_request.model,
        )
    else:
        answer = withheld_response(result)
    return {
        **result, "allowed": allowed, "ai_response": answer,
        "total_latency_ms": round((time.perf_counter() - start) * 1000, 3),
    }
