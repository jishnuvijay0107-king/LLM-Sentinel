from datetime import datetime
from pathlib import Path
import json

from evaluation.dataset import EVALUATION_CASES
from evaluation.evaluator import evaluate_dataset
from evaluation.metrics import calculate_metrics
from evaluation.category_metrics import calculate_category_metrics
from evaluation.robustness import run_robustness_tests


REPORT_DIR = Path("evaluation/reports")


def generate_report():
    """
    Generate a complete LLM-Sentinel security evaluation report.
    """

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ------------------------------------------------------------
    # MAIN DATASET EVALUATION
    # ------------------------------------------------------------

    evaluation_results = evaluate_dataset(
        EVALUATION_CASES
    )

    metrics = calculate_metrics(
        evaluation_results
    )

    category_metrics = calculate_category_metrics(
        evaluation_results
    )

    # ------------------------------------------------------------
    # ROBUSTNESS EVALUATION
    # ------------------------------------------------------------

    robustness_results = run_robustness_tests()

    robustness_total = len(
        robustness_results
    )

    robustness_passed = sum(
        1
        for result in robustness_results
        if result["passed"]
    )

    robustness_failed = (
        robustness_total
        - robustness_passed
    )

    robustness_pass_rate = (
        robustness_passed
        / robustness_total
        * 100
        if robustness_total
        else 0
    )

    # ------------------------------------------------------------
    # TIMESTAMP
    # ------------------------------------------------------------

    generated_at = datetime.now().astimezone()

    # ------------------------------------------------------------
    # TEXT REPORT
    # ------------------------------------------------------------

    report_lines = []

    report_lines.append(
        "LLM-Sentinel Security Evaluation Report"
    )

    report_lines.append(
        "=" * 60
    )

    report_lines.append(
        f"Generated: {generated_at.isoformat()}"
    )

    report_lines.append("")

    # ------------------------------------------------------------
    # DATASET
    # ------------------------------------------------------------

    report_lines.append(
        "1. Evaluation Dataset"
    )

    report_lines.append(
        "-" * 60
    )

    report_lines.append(
        f"Total cases       : {metrics['total_cases']}"
    )

    report_lines.append(
        f"Attack cases      : {metrics['attack_cases']}"
    )

    report_lines.append(
        f"Benign cases      : {metrics['benign_cases']}"
    )

    report_lines.append("")

    # ------------------------------------------------------------
    # CONFUSION MATRIX
    # ------------------------------------------------------------

    report_lines.append(
        "2. Confusion Matrix"
    )

    report_lines.append(
        "-" * 60
    )

    report_lines.append(
        f"True Positives    : {metrics['true_positive']}"
    )

    report_lines.append(
        f"True Negatives    : {metrics['true_negative']}"
    )

    report_lines.append(
        f"False Positives   : {metrics['false_positive']}"
    )

    report_lines.append(
        f"False Negatives   : {metrics['false_negative']}"
    )

    report_lines.append("")

    # ------------------------------------------------------------
    # SECURITY PERFORMANCE
    # ------------------------------------------------------------

    report_lines.append(
        "3. Security Performance"
    )

    report_lines.append(
        "-" * 60
    )

    report_lines.append(
        f"Detection Rate     : "
        f"{metrics['detection_rate']:.2f}%"
    )

    report_lines.append(
        f"False Positive Rate: "
        f"{metrics['false_positive_rate']:.2f}%"
    )

    report_lines.append(
        f"False Negative Rate: "
        f"{metrics['false_negative_rate']:.2f}%"
    )

    report_lines.append(
        f"Accuracy           : "
        f"{metrics['accuracy']:.2f}%"
    )

    report_lines.append("")

    # ------------------------------------------------------------
    # CATEGORY METRICS
    # ------------------------------------------------------------

    report_lines.append(
        "4. Detection by Security Category"
    )

    report_lines.append(
        "-" * 60
    )

    for category, data in category_metrics.items():

        report_lines.append(
            f"{category:<30}"
            f"{data['detected']}/"
            f"{data['expected']} "
            f"({data['detection_rate']:.2f}%)"
        )

    report_lines.append("")

    # ------------------------------------------------------------
    # ROBUSTNESS
    # ------------------------------------------------------------

    report_lines.append(
        "5. Robustness Evaluation"
    )

    report_lines.append(
        "-" * 60
    )

    report_lines.append(
        f"Total cases : {robustness_total}"
    )

    report_lines.append(
        f"Passed      : {robustness_passed}"
    )

    report_lines.append(
        f"Failed      : {robustness_failed}"
    )

    report_lines.append(
        f"Pass rate   : {robustness_pass_rate:.2f}%"
    )

    report_lines.append("")

    # ------------------------------------------------------------
    # TEST DETAILS
    # ------------------------------------------------------------

    report_lines.append(
        "6. Robustness Test Details"
    )

    report_lines.append(
        "-" * 60
    )

    for result in robustness_results:

        status = (
            "PASS"
            if result["passed"]
            else "FAIL"
        )

        report_lines.append(
            f"{result['name']:<35}"
            f"{status:<8}"
            f"expected={result['expected_attack']!s:<6}"
            f"detected={result['detected']!s:<6}"
        )

    report_lines.append("")

    # ------------------------------------------------------------
    # SECURITY NOTE
    # ------------------------------------------------------------

    report_lines.append(
        "7. Evaluation Scope"
    )

    report_lines.append(
        "-" * 60
    )

    report_lines.append(
        "These results represent performance on the "
        "current handcrafted evaluation dataset."
    )

    report_lines.append(
        "They should not be interpreted as real-world "
        "detection accuracy."
    )

    report_lines.append(
        "Additional datasets and adversarial testing "
        "are required for broader validation."
    )

    report_lines.append("")

    report_lines.append(
        "=" * 60
    )

    report_lines.append(
        "End of LLM-Sentinel Security Evaluation Report"
    )

    # ------------------------------------------------------------
    # SAVE TEXT REPORT
    # ------------------------------------------------------------

    text_report = "\n".join(
        report_lines
    )

    text_path = (
        REPORT_DIR
        / "security_evaluation_report.txt"
    )

    text_path.write_text(
        text_report,
        encoding="utf-8",
    )

    # ------------------------------------------------------------
    # SAVE JSON REPORT
    # ------------------------------------------------------------

    json_report = {
        "generated_at": generated_at.isoformat(),

        "dataset": {
            "total_cases": metrics["total_cases"],
            "attack_cases": metrics["attack_cases"],
            "benign_cases": metrics["benign_cases"],
        },

        "confusion_matrix": {
            "true_positive": metrics["true_positive"],
            "true_negative": metrics["true_negative"],
            "false_positive": metrics["false_positive"],
            "false_negative": metrics["false_negative"],
        },

        "security_performance": {
            "detection_rate": metrics[
                "detection_rate"
            ],
            "false_positive_rate": metrics[
                "false_positive_rate"
            ],
            "false_negative_rate": metrics[
                "false_negative_rate"
            ],
            "accuracy": metrics["accuracy"],
        },

        "category_metrics": category_metrics,

        "robustness": {
            "total_cases": robustness_total,
            "passed": robustness_passed,
            "failed": robustness_failed,
            "pass_rate": robustness_pass_rate,
        },
    }

    json_path = (
        REPORT_DIR
        / "security_evaluation_report.json"
    )

    json_path.write_text(
        json.dumps(
            json_report,
            indent=4,
        ),
        encoding="utf-8",
    )

    return text_path, json_path


def main():
    text_path, json_path = generate_report()

    print()
    print(
        "LLM-Sentinel Evaluation Report Generated"
    )
    print("=" * 50)

    print(
        f"Text report : {text_path}"
    )

    print(
        f"JSON report : {json_path}"
    )

    print("=" * 50)


if __name__ == "__main__":
    main()