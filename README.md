# OpenGrep Rule Agent

AI-powered agent that creates high-quality, original OpenGrep security scanner rules for Python, tested and scored against [OWASP BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython).

## Overview

This project uses GitHub Copilot agents and skills to:
1. **Analyze** Python vulnerability patterns in OWASP BenchmarkPython
2. **Generate** original OpenGrep rules (never copying from existing rule repos)
3. **Test** rules against 1,230 benchmark test cases across 14 CWE categories
4. **Score** results using TPR/FPR metrics with a Youden Index
5. **Iterate** until rules achieve "SUPER" grade (TPR > 90%, FPR < 10%)

## Quick Start

```bash
# Clone this repo
git clone https://github.com/DimaBir/opengrep-rule-agent.git
cd opengrep-rule-agent

# Install opengrep
pip install opengrep

# Clone the benchmark
git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git benchmark/

# Run a scan
python scripts/run_scan.py --category sqli

# Score results
python scripts/score.py output/results.json benchmark/expectedresults-0.1.csv
```

## Vulnerability Categories

| CWE | Category | Description |
|-----|----------|-------------|
| CWE-78 | Command Injection | User input in shell commands |
| CWE-79 | XSS | User input in HTML output |
| CWE-89 | SQL Injection | User input in SQL queries |
| CWE-90 | LDAP Injection | User input in LDAP queries |
| CWE-22 | Path Traversal | User input in file paths |
| CWE-327 | Weak Crypto | Deprecated cryptographic algorithms |
| CWE-328 | Weak Hash | MD5/SHA1 for security purposes |
| CWE-330 | Weak Random | Predictable random for security |
| CWE-501 | Trust Boundary | Unvalidated data in trusted store |
| CWE-502 | Deserialization | Deserializing untrusted data |
| CWE-601 | Open Redirect | User input in redirect URLs |
| CWE-611 | XXE | XML parsing with external entities |
| CWE-614 | Insecure Cookie | Cookies without secure flags |
| CWE-643 | XPath Injection | User input in XPath expressions |

## GitHub Copilot Agents

- **Rule-Creator** — Creates original OpenGrep rules for a given CWE category
- **Rule-Analyzer** — Analyzes benchmark test cases to understand vulnerability patterns
- **Rule-Tester** — Runs and scores rules against the benchmark

## License

MIT
