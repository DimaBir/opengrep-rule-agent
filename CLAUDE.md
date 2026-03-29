# OpenGrep Rule Agent

## Project Purpose
AI-powered agent that creates high-quality, original OpenGrep security scanner rules tested against OWASP BenchmarkPython.

## Key Constraints
- **NEVER copy rules** from semgrep-rules or opengrep-rules — all rules must be original
- Rules are YAML files compatible with OpenGrep (semgrep-compatible syntax)
- Target: Python security vulnerabilities mapped to CWE categories
- Quality target: TPR > 90%, FPR < 10% (Youden Index > 0.80 = "SUPER" grade)

## Project Structure
- `.github/skills/opengrep/SKILL.md` — Complete reference for rule syntax and vulnerability categories
- `.github/agents/` — Copilot agents (rule-creator, rule-analyzer, rule-tester)
- `rules/python/<category>/` — Generated rules organized by CWE category
- `benchmark/` — OWASP BenchmarkPython (clone with `git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git benchmark/`)
- `scripts/score.py` — Score results against expected results
- `scripts/run_scan.py` — Run opengrep against benchmark
- `output/` — Scan results and score reports

## Workflow
1. `python scripts/run_scan.py --category sqli` — Run scan for a category
2. `python scripts/score.py output/results.json benchmark/expectedresults-0.1.csv` — Score results
3. Iterate rules until SUPER grade achieved

## Setup
```bash
# Install opengrep
pip install opengrep  # or: curl -sSL https://get.opengrep.dev | bash

# Clone benchmark
git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git benchmark/
```
