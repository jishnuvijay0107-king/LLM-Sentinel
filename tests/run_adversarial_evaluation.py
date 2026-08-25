import json
from pathlib import Path

from security.detector import detect_prompt_injection


DATASET_PATH = (
    Path(__file__).resolve().parent.parent
    / "datasets"
    / "adversarial_tests.json"
)


def main():
    with open(DATASET_PATH, "r", encoding="utf-8") as file:
        dataset = json.load(file)

    correct = 0
    incorrect = 0

    print("\n=== LLM-Sentinel Adversarial Evaluation ===\n")

    for case in dataset:
        detections = detect_prompt_injection(case["prompt"])

        actual_detection = len(detections) > 0
        expected_detection = case["expected_detection"]

        passed = actual_detection == expected_detection

        if passed:
            correct += 1
            status = "PASS"
        else:
            incorrect += 1
            status = "FAIL"

        print(
            f"{case['id']:10} "
            f"{case['category']:30} "
            f"{status}"
        )

    total = len(dataset)

    accuracy = correct / total if total else 0

    print("\n=== Adversarial Results ===\n")
    print(f"Total Cases : {total}")
    print(f"Passed      : {correct}")
    print(f"Failed      : {incorrect}")
    print(f"Accuracy    : {accuracy:.2%}")


if __name__ == "__main__":
    main()