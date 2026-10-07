from dataclasses import dataclass

from evaluation.dataset import EVALUATION_CASES, EvaluationCase
from security.detector import detect_prompt_injection
from security.obfuscation_detector import detect_obfuscation


@dataclass
class EvaluationResult:
    name: str
    is_attack: bool
    detected: bool
    expected_categories: tuple[str, ...]
    actual_categories: tuple[str, ...]


def evaluate_case(case: EvaluationCase) -> EvaluationResult:
    injection_detections = detect_prompt_injection(case.prompt)
    obfuscation_detections = detect_obfuscation(case.prompt)

    detections = injection_detections + obfuscation_detections

    actual_categories = tuple(
        sorted(
            {
                detection.category
                for detection in detections
            }
        )
    )

    detected = len(actual_categories) > 0

    return EvaluationResult(
        name=case.name,
        is_attack=case.is_attack,
        detected=detected,
        expected_categories=case.expected_categories,
        actual_categories=actual_categories,
    )


def evaluate_dataset(
    cases: list[EvaluationCase],
) -> list[EvaluationResult]:
    return [
        evaluate_case(case)
        for case in cases
    ]


def main() -> None:
    results = evaluate_dataset(EVALUATION_CASES)

    print("\nLLM-Sentinel Security Evaluation")
    print("=" * 50)

    for result in results:
        status = "DETECTED" if result.detected else "CLEAN"

        print(
            f"{result.name:<30} "
            f"{status:<10} "
            f"categories={result.actual_categories}"
        )

    print("=" * 50)
    print(f"Total cases: {len(results)}")


if __name__ == "__main__":
    main()