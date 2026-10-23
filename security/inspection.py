"""The inspection contract shared by the API, dashboard, and evaluation."""

from dataclasses import asdict
from time import perf_counter

from security.detector import detect_prompt_injection
from security.normalizer import normalize_text
from security.obfuscation_detector import detect_obfuscation
from security.policy_engine import make_decision
from security.risk_engine import calculate_risk, get_risk_level


def inspect_prompt(prompt: str) -> dict:
    if not prompt.strip() or len(prompt) > 10000:
        raise ValueError("Enter between 1 and 10,000 characters, including non-whitespace text.")
    start = perf_counter()
    detections = (
        detect_prompt_injection(normalize_text(prompt))
        + detect_obfuscation(prompt)
    )
    score = calculate_risk(detections)
    return {
        "risk_score": score,
        "risk_level": get_risk_level(score),
        "decision": make_decision(score),
        "detections": [asdict(d) for d in detections],
        "latency_ms": round((perf_counter() - start) * 1000, 3),
    }


def withheld_response(result: dict) -> str:
    risk = f"Risk level: {result['risk_level'].capitalize()} ({result['risk_score']}/100). "
    if result["decision"] == "BLOCK":
        return "Security Alert: request blocked. " + risk + "The prompt matched a security rule and was not sent to the model."
    return "Request withheld for review. " + risk + "Check the inspection evidence or revise your prompt. It was not sent to the model."
