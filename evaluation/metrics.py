from evaluation.dataset import EVALUATION_CASES
from evaluation.evaluator import evaluate_dataset


def calculate_metrics(results):
    total = len(results)

    attack_cases = [
        result
        for result in results
        if result.is_attack
    ]

    benign_cases = [
        result
        for result in results
        if not result.is_attack
    ]

    true_positive = sum(
        1
        for result in attack_cases
        if result.detected
    )

    false_negative = sum(
        1
        for result in attack_cases
        if not result.detected
    )

    false_positive = sum(
        1
        for result in benign_cases
        if result.detected
    )

    true_negative = sum(
        1
        for result in benign_cases
        if not result.detected
    )

    detection_rate = (
        true_positive / len(attack_cases) * 100
        if attack_cases
        else 0
    )

    false_positive_rate = (
        false_positive / len(benign_cases) * 100
        if benign_cases
        else 0
    )

    false_negative_rate = (
        false_negative / len(attack_cases) * 100
        if attack_cases
        else 0
    )

    accuracy = (
        (true_positive + true_negative) / total * 100
        if total
        else 0
    )

    return {
        "total_cases": total,
        "attack_cases": len(attack_cases),
        "benign_cases": len(benign_cases),
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "detection_rate": detection_rate,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "accuracy": accuracy,
    }


def main():
    results = evaluate_dataset(EVALUATION_CASES)

    metrics = calculate_metrics(results)

    print("\nLLM-Sentinel Security Metrics")
    print("=" * 50)

    print(
        f"Total cases       : "
        f"{metrics['total_cases']}"
    )

    print(
        f"Attack cases      : "
        f"{metrics['attack_cases']}"
    )

    print(
        f"Benign cases      : "
        f"{metrics['benign_cases']}"
    )

    print("\nConfusion Matrix")
    print("-" * 30)

    print(
        f"True Positives    : "
        f"{metrics['true_positive']}"
    )

    print(
        f"True Negatives    : "
        f"{metrics['true_negative']}"
    )

    print(
        f"False Positives   : "
        f"{metrics['false_positive']}"
    )

    print(
        f"False Negatives   : "
        f"{metrics['false_negative']}"
    )

    print("\nSecurity Performance")
    print("-" * 30)

    print(
        f"Detection Rate    : "
        f"{metrics['detection_rate']:.2f}%"
    )

    print(
        f"False Positive Rate: "
        f"{metrics['false_positive_rate']:.2f}%"
    )

    print(
        f"False Negative Rate: "
        f"{metrics['false_negative_rate']:.2f}%"
    )

    print(
        f"Accuracy           : "
        f"{metrics['accuracy']:.2f}%"
    )

    print("=" * 50)


if __name__ == "__main__":
    main()