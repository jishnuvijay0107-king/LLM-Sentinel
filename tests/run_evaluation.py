from security.evaluator import evaluate_dataset


def main():
    report = evaluate_dataset()

    print("\n=== LLM-Sentinel Security Evaluation ===\n")

    print(f"Total Cases      : {report['total_cases']}")
    print(f"True Positives   : {report['true_positive']}")
    print(f"True Negatives   : {report['true_negative']}")
    print(f"False Positives  : {report['false_positive']}")
    print(f"False Negatives  : {report['false_negative']}")

    print(f"\nAccuracy         : {report['accuracy']:.2%}")
    print(f"Precision        : {report['precision']:.2%}")
    print(f"Recall           : {report['recall']:.2%}")
    print(f"F1 Score         : {report['f1_score']:.2%}")
    print(f"Attack Containment: {report['containment_rate']:.2%}")
    print(f"Benign Withheld  : {report['benign_withheld']}")

    print("\n=== Case Results ===\n")

    for result in report["results"]:
        print(
            f"{result['id']:12} "
            f"{result['category']:25} "
            f"{result['result']}"
        )

    if report["false_positive"] or report["false_negative"] or report["benign_withheld"] or report["containment_rate"] < 1:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
