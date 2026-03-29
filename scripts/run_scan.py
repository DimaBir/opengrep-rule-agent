#!/usr/bin/env python3
"""Run OpenGrep scan against OWASP BenchmarkPython."""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def run_opengrep(rules_path: str, target_path: str, output_path: str) -> int:
    """Run opengrep and save JSON results."""
    cmd = [
        "opengrep",
        "--config", rules_path,
        "--json",
        target_path,
    ]

    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode not in (0, 1):  # 1 = findings found (expected)
        print(f"Error running opengrep: {result.stderr}", file=sys.stderr)
        return result.returncode

    # Parse and save results
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    try:
        data = json.loads(result.stdout)
        with open(output, "w") as f:
            json.dump(data, f, indent=2)
        findings = data if isinstance(data, list) else data.get("results", [])
        print(f"Scan complete: {len(findings)} findings saved to {output}")
    except json.JSONDecodeError:
        print(f"Warning: Could not parse JSON output. Raw output saved.")
        with open(output, "w") as f:
            f.write(result.stdout)

    return 0


def main():
    parser = argparse.ArgumentParser(description="Run OpenGrep scan against benchmark")
    parser.add_argument("--rules", default="rules/python/", help="Path to rules directory")
    parser.add_argument("--target", default="benchmark/testcode/", help="Path to target code")
    parser.add_argument("--output", default="output/results.json", help="Path for JSON output")
    parser.add_argument("--category", help="Scan only a specific category subfolder (e.g., sqli)")
    args = parser.parse_args()

    rules_path = args.rules
    if args.category:
        rules_path = f"{args.rules.rstrip('/')}/{args.category}/"

    sys.exit(run_opengrep(rules_path, args.target, args.output))


if __name__ == "__main__":
    main()
