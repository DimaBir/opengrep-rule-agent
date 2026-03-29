#!/usr/bin/env python3
"""Score OpenGrep scan results against OWASP BenchmarkPython expected results."""

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path


def load_expected_results(csv_path: str) -> dict:
    """Load expected results CSV. Returns {test_name: {cwe, category, vulnerable}}."""
    results = {}
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Handle various CSV formats
            test_name = row.get("# test name", row.get("test_name", row.get("Test", "")))
            test_name = test_name.strip()
            cwe = row.get("CWE", row.get("cwe", "")).strip()
            category = row.get("category", row.get("Category", "")).strip()
            vulnerable = row.get("real vulnerability", row.get("vulnerable", "")).strip().lower() == "true"
            if test_name:
                results[test_name] = {
                    "cwe": cwe,
                    "category": category,
                    "vulnerable": vulnerable,
                }
    return results


def load_scan_results(json_path: str) -> set:
    """Load OpenGrep JSON output. Returns set of test file basenames that had findings."""
    flagged = set()
    with open(json_path, "r") as f:
        data = json.load(f)

    results = data if isinstance(data, list) else data.get("results", [])
    for result in results:
        path = result.get("path", "")
        basename = Path(path).stem
        flagged.add(basename)

    return flagged


def score(expected: dict, flagged: set, cwe_filter: str = None) -> dict:
    """Calculate TPR, FPR, and Youden Index."""
    tp = fp = tn = fn = 0

    for test_name, info in expected.items():
        if cwe_filter and info["cwe"] != cwe_filter:
            continue

        is_flagged = test_name in flagged
        is_vulnerable = info["vulnerable"]

        if is_vulnerable and is_flagged:
            tp += 1
        elif is_vulnerable and not is_flagged:
            fn += 1
        elif not is_vulnerable and is_flagged:
            fp += 1
        else:
            tn += 1

    total_positive = tp + fn
    total_negative = fp + tn
    tpr = tp / total_positive if total_positive > 0 else 0
    fpr = fp / total_negative if total_negative > 0 else 0
    youden = tpr - fpr

    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "tpr": tpr, "fpr": fpr, "youden": youden,
        "total": tp + fn + fp + tn,
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: python score.py <scan_results.json> <expected_results.csv> [CWE-number]")
        print("Example: python score.py output/results.json benchmark/expectedresults-0.1.csv CWE-89")
        sys.exit(1)

    scan_path = sys.argv[1]
    expected_path = sys.argv[2]
    cwe_filter = sys.argv[3] if len(sys.argv) > 3 else None

    expected = load_expected_results(expected_path)
    flagged = load_scan_results(scan_path)

    if cwe_filter:
        # Score single CWE
        result = score(expected, flagged, cwe_filter)
        grade = "SUPER" if result["youden"] > 0.8 else "GOOD" if result["youden"] > 0.5 else "NEEDS_WORK"
        print(f"\n{'='*50}")
        print(f"  {cwe_filter} Score Report")
        print(f"{'='*50}")
        print(f"  TPR: {result['tpr']:.1%} (TP={result['tp']}, FN={result['fn']})")
        print(f"  FPR: {result['fpr']:.1%} (FP={result['fp']}, TN={result['tn']})")
        print(f"  Youden Index: {result['youden']:.3f}")
        print(f"  Grade: {grade}")
        print(f"  Total test cases: {result['total']}")
        print(f"{'='*50}\n")
    else:
        # Score all CWEs
        cwes = sorted(set(info["cwe"] for info in expected.values() if info["cwe"]))
        print(f"\n{'='*70}")
        print(f"  Overall Score Report")
        print(f"{'='*70}")
        print(f"  {'CWE':<12} {'TPR':>6} {'FPR':>6} {'Youden':>8} {'Grade':<12} {'Tests':>6}")
        print(f"  {'-'*12} {'-'*6} {'-'*6} {'-'*8} {'-'*12} {'-'*6}")

        for cwe in cwes:
            result = score(expected, flagged, cwe)
            if result["total"] == 0:
                continue
            grade = "SUPER" if result["youden"] > 0.8 else "GOOD" if result["youden"] > 0.5 else "NEEDS_WORK"
            print(f"  {cwe:<12} {result['tpr']:>5.1%} {result['fpr']:>5.1%} {result['youden']:>7.3f}  {grade:<12} {result['total']:>5}")

        # Overall
        overall = score(expected, flagged)
        grade = "SUPER" if overall["youden"] > 0.8 else "GOOD" if overall["youden"] > 0.5 else "NEEDS_WORK"
        print(f"  {'-'*12} {'-'*6} {'-'*6} {'-'*8} {'-'*12} {'-'*6}")
        print(f"  {'OVERALL':<12} {overall['tpr']:>5.1%} {overall['fpr']:>5.1%} {overall['youden']:>7.3f}  {grade:<12} {overall['total']:>5}")
        print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
