import time
from fastapi import APIRouter, Request

from backend.app.models import (
    GuardedChatRequest,
    GuardedChatResponse,
    SecurityAnalysisRequest,
    SecurityAnalysisResponse,
)

from backend.app.rate_limiter import limiter
from backend.app.llm_client import generate_llm_response

from security.normalizer import normalize_text
from security.detector import detect_prompt_injection
from security.obfuscation_detector import detect_obfuscation
from security.risk_engine import calculate_risk, get_risk_level
from security.policy_engine import make_decision
from security.logger import log_security_event


router = APIRouter(
    prefix="/api/v1/security",
    tags=["Security Analysis"],
)


def _generate_assistant_response(prompt: str) -> str:
    """
    Simulate or generate an assistant response for permitted prompts.
    Provides helpful and realistic AI output when prompts pass security inspection.
    """
    clean_p = prompt.strip().lower()

    if "capital" in clean_p and "france" in clean_p:
        return "The capital of France is Paris."
    elif "http" in clean_p:
        return (
            "HTTP (Hypertext Transfer Protocol) is an application-layer protocol "
            "for transmitting hypermedia documents. It functions as a request-response "
            "protocol in the client-server computing model."
        )
    elif "python" in clean_p and "list" in clean_p:
        return (
            "In Python, a list is an ordered, mutable sequence of items. You can create "
            "one using square brackets: `my_list = [1, 2, 'hello']`."
        )
    elif "firewall" in clean_p:
        return (
            "A firewall is a network security device that monitors and filters incoming "
            "and outgoing network traffic based on an organization's previously established security policies."
        )
    else:
        return (
            f"✅ [LLM-Sentinel Guardrail Passed]: Your query was analyzed and verified safe. "
            f"Here is the assistant response to: '{prompt.strip()[:100]}...'\n\n"
            f"Your request has been successfully processed by the downstream language model."
        )


@router.post(
    "/analyze",
    response_model=SecurityAnalysisResponse,
)
@limiter.limit("60/minute")
def analyze_prompt(
    request: Request,
    analysis_request: SecurityAnalysisRequest,
):
    """
    Analyze user input for prompt injection
    and character-level obfuscation.
    """
    start_time = time.perf_counter()

    original_prompt = analysis_request.prompt

    normalized_prompt = normalize_text(
        original_prompt
    )

    injection_detections = detect_prompt_injection(
        normalized_prompt
    )

    obfuscation_detections = detect_obfuscation(
        original_prompt
    )

    detections = (
        injection_detections
        + obfuscation_detections
    )

    risk_score = calculate_risk(
        detections
    )

    risk_level = get_risk_level(
        risk_score
    )

    decision = make_decision(
        risk_score
    )

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    response_detections = [
        {
            "category": detection.category,
            "confidence": detection.confidence,
            "reason": detection.reason,
        }
        for detection in detections
    ]

    event = log_security_event(
        risk_score=risk_score,
        risk_level=risk_level,
        decision=decision,
        detections=response_detections,
    )

    return SecurityAnalysisResponse(
        event_id=event["event_id"],
        timestamp=event["timestamp"],
        risk_score=risk_score,
        risk_level=risk_level,
        decision=decision,
        detections=response_detections,
        latency_ms=latency_ms,
    )


@router.post(
    "/chat",
    response_model=GuardedChatResponse,
)
@limiter.limit("60/minute")
def guarded_chat(
    request: Request,
    chat_request: GuardedChatRequest,
):
    """
    Guarded Chat Endpoint: Inspects prompt first. If safe, forwards to AI.
    If malicious, intercepts request and returns security block diagnostics.
    """
    start_time = time.perf_counter()

    original_prompt = chat_request.prompt
    normalized_prompt = normalize_text(original_prompt)

    injection_detections = detect_prompt_injection(normalized_prompt)
    obfuscation_detections = detect_obfuscation(original_prompt)

    detections = injection_detections + obfuscation_detections
    risk_score = calculate_risk(detections)
    risk_level = get_risk_level(risk_score)
    decision = make_decision(risk_score)

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    response_detections = [
        {
            "category": detection.category,
            "confidence": detection.confidence,
            "reason": detection.reason,
        }
        for detection in detections
    ]

    event = log_security_event(
        risk_score=risk_score,
        risk_level=risk_level,
        decision=decision,
        detections=response_detections,
    )

    if decision == "BLOCK":
        reasons = [d["reason"] for d in response_detections]
        ai_response = (
            f"🛡️ **Security Alert: Prompt Intercepted by LLM-Sentinel**\n\n"
            f"**Threat Severity:** {risk_level} (Score: {risk_score}/100)\n\n"
            f"**Triggers Identified:**\n"
            + "\n".join(f"- {r}" for r in reasons)
            + "\n\n*This prompt was blocked at the gateway and never reached the underlying LLM to protect system integrity.*"
        )
        allowed = False
    else:
        ai_response = generate_llm_response(
            prompt=original_prompt,
            provider=chat_request.provider,
            api_key=chat_request.api_key,
            model=chat_request.model,
        )
        allowed = True

    return GuardedChatResponse(
        event_id=event["event_id"],
        allowed=allowed,
        decision=decision,
        risk_score=risk_score,
        risk_level=risk_level,
        detections=response_detections,
        ai_response=ai_response,
        latency_ms=latency_ms,
    )