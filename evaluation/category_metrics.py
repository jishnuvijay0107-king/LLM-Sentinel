from collections import Counter

from evaluation.dataset import EVALUATION_CASES
from evaluation.evaluator import evaluate_dataset


def calculate_category_metrics(results):
    expected = Counter()
    detected = Counter()

    for result in results:
        for category in result.expected_categories:
            expected[category] += 1

        for category in result.actual_categories:
            detected[category] += 1

    categories = sorted(
        set(expected) | set(detected)
    )

    metrics = {}

    for category in categories:
        expected_count = expected[category]
        detected_count = detected[category]

        if expected_count:
            detection_rate = (
                detected_count / expected_count
            ) * 100
        else:
            detection_rate = 0

        metrics[category] = {
            "expected": expected_count,
            "detected": detected_count,
            "detection_rate": detection_rate,
        }

    return metrics


def main():
    results = evaluate_dataset(EVALUATION_CASES)

    metrics = calculate_category_metrics(results)

    print("\nLLM-Sentinel Category Metrics")
    print("=" * 60)

    for category, data in metrics.items():
        print(
            f"{category:<30}"
            f" expected={data['expected']:<3} "
            f"detected={data['detected']:<3} "
            f"rate={data['detection_rate']:.2f}%"
        )

    print("=" * 60)


if __name__ == "__main__":
    main()