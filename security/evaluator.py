import json
from pathlib import Path

from security.detector import detect_prompt_injection
from security.obfuscation_detector import detect_obfuscation


DATASET_PATH = (
    Path(__file__).resolve().parent.parent
    / "datasets"
    / "prompt_injection_tests.json"
)


def load_dataset():
    """Load security test cases from the evaluation dataset."""

    with open(DATASET_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def evaluate_dataset():
    """Evaluate the detector against the complete test dataset."""

    dataset = load_dataset()

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    results = []

    for case in dataset:
        detections = detect_prompt_injection(case["prompt"]) + detect_obfuscation(case["prompt"])

        actual_detection = len(detections) > 0
        expected_detection = case["expected_detection"]

        if expected_detection and actual_detection:
            true_positive += 1
            result = "TP"

        elif not expected_detection and not actual_detection:
            true_negative += 1
            result = "TN"

        elif not expected_detection and actual_detection:
            false_positive += 1
            result = "FP"

        else:
            false_negative += 1
            result = "FN"

        results.append(
            {
                "id": case["id"],
                "category": case["category"],
                "expected_detection": expected_detection,
                "actual_detection": actual_detection,
                "result": result,
            }
        )

    total = len(dataset)

    accuracy = (
        (true_positive + true_negative) / total
        if total
        else 0
    )

    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive)
        else 0
    )

    recall = (
        true_positive / (true_positive + false_negative)
        if (true_positive + false_negative)
        else 0
    )

    f1_score = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0
    )

    return {
        "total_cases": total,
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "results": results,
    }