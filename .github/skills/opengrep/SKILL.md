# OpenGrep Rule Creation Skill

## Description
This skill guides the creation of high-quality, original OpenGrep security scanner rules. It encodes deep knowledge of rule syntax, pattern-writing techniques, vulnerability categories, and testing methodology against the OWASP BenchmarkPython.

**IMPORTANT**: All rules must be original. Do NOT copy rules from semgrep-rules or opengrep-rules repositories. Learn from the patterns and techniques, then create novel, high-quality rules.

---

## OpenGrep Overview

OpenGrep is an open-source fork of Semgrep v1.100.0 (LGPL 2.1 licensed). It uses identical YAML rule syntax but adds:
- Enhanced taint analysis (`--taint-intrafile`) with constructor tracking and inter-method taint flow
- Additional language support (Visual Basic, Apex, Elixir)
- Self-contained binaries (no Python runtime needed)

### Installation
```bash
# Linux/macOS
curl -sSL https://get.opengrep.dev | bash

# Or via pip
pip install opengrep

# Verify
opengrep --version
```

### Running Rules
```bash
# Run a single rule file
opengrep --config path/to/rule.yaml path/to/target/code/

# Run all rules in a directory
opengrep --config rules/ path/to/target/code/

# Run with JSON output for scoring
opengrep --config rules/ --json path/to/target/code/ > output/results.json

# Run with verbose output
opengrep --config rules/ --verbose path/to/target/code/
```

---

## Rule YAML Schema

### Minimal Rule
```yaml
rules:
  - id: python-sql-injection-format-string
    pattern: cursor.execute(f"...{$USERINPUT}...")
    message: >
      SQL injection via f-string interpolation in cursor.execute().
      Use parameterized queries instead: cursor.execute("SELECT ...", (param,))
    languages: [python]
    severity: ERROR
```

### Complete Rule Schema
```yaml
rules:
  - id: <unique-rule-id>            # Required. Lowercase kebab-case. e.g., python-sqli-format-string

    # --- Pattern (exactly ONE of these is required) ---
    pattern: <pattern>               # Single pattern to match
    patterns:                        # AND - all must match
      - pattern: <p1>
      - pattern: <p2>
    pattern-either:                  # OR - any can match
      - pattern: <p1>
      - pattern: <p2>
    pattern-regex: <regex>           # Regex-based matching

    # --- Pattern Modifiers (used inside patterns/pattern-either) ---
    # pattern-not: <pattern>         # Exclude matches
    # pattern-inside: <pattern>      # Match must be inside this
    # pattern-not-inside: <pattern>  # Match must NOT be inside this
    # metavariable-regex:            # Filter metavariable by regex
    #   metavariable: $VAR
    #   regex: "dangerous_.*"
    # metavariable-pattern:          # Filter metavariable by pattern
    #   metavariable: $VAR
    #   pattern: <sub-pattern>
    # metavariable-comparison:       # Numeric comparison on metavariable
    #   metavariable: $VAR
    #   comparison: $VAR > 10
    # focus-metavariable: $VAR       # Narrow the match to just this metavar

    message: <string>                # Required. Explain vulnerability + remediation
    languages: [python]              # Required. Target language(s)
    severity: ERROR|WARNING|INFO     # Required. ERROR=vulnerability, WARNING=potential issue, INFO=audit

    # --- Optional Fields ---
    metadata:                        # Arbitrary metadata
      cwe:
        - "CWE-89: SQL Injection"
      owasp:
        - "A03:2021 - Injection"
      confidence: HIGH|MEDIUM|LOW
      impact: HIGH|MEDIUM|LOW
      category: security
      technology:
        - flask
        - django
      references:
        - https://example.com/guidance

    fix: <replacement-pattern>       # Auto-fix suggestion
    fix-regex:                       # Regex-based auto-fix
      regex: <find>
      replacement: <replace>

    paths:                           # File path filters
      include:
        - "app/**/*.py"
      exclude:
        - "tests/**"

    options:                         # Matching options
      symbolic_propagation: true     # Follow variable assignments
      constant_propagation: true     # Track constant values (default: true)
```

---

## Metavariable Reference

| Metavariable | Matches | Example |
|-------------|---------|---------|
| `$X`, `$VAR` | Any single expression | `foo($X)` matches `foo(42)`, `foo(bar)` |
| `$...ARGS` | Zero or more arguments (spread) | `foo($...ARGS)` matches `foo()`, `foo(1,2,3)` |
| `$_` | Any expression (anonymous, no binding) | `foo($_, $X)` matches any first arg |
| `...` | Zero or more statements (ellipsis) | `if ...: ... $DANGEROUS ...` |

### Metavariable Naming Conventions
- Use descriptive names: `$USER_INPUT`, `$QUERY`, `$FILENAME`, `$CIPHER`
- Use `$FUNC` for function names, `$CLASS` for class names
- Use `$...ARGS` for variable-length argument lists

---

## Pattern Operators Deep Dive

### AND (patterns) - All Must Match
```yaml
patterns:
  - pattern: $RESULT = hashlib.$ALGO($...)
  - metavariable-regex:
      metavariable: $ALGO
      regex: "^(md5|sha1)$"
```
Matches: `h = hashlib.md5(data)` but NOT `h = hashlib.sha256(data)`

### OR (pattern-either) - Any Can Match
```yaml
pattern-either:
  - pattern: os.system($CMD)
  - pattern: subprocess.call($CMD, shell=True)
  - pattern: subprocess.Popen($CMD, shell=True)
```

### NOT (pattern-not) - Exclude Matches
```yaml
patterns:
  - pattern: cursor.execute($QUERY, ...)
  - pattern-not: cursor.execute("...", ...)
```
Matches dynamic queries but NOT hardcoded string literals.

### INSIDE/NOT-INSIDE - Scope Constraints
```yaml
patterns:
  - pattern: $COOKIE = ...
  - pattern-inside: |
      def $FUNC(...):
          ...
  - pattern-not-inside: |
      $COOKIE.set_cookie(..., secure=True, ...)
```

### Taint Analysis (Advanced)
```yaml
rules:
  - id: taint-sqli
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
      - pattern: request.form[...]
    pattern-sinks:
      - pattern: cursor.execute($QUERY, ...)
        focus-metavariable: $QUERY
      - pattern: db.engine.execute($QUERY)
        focus-metavariable: $QUERY
    pattern-sanitizers:
      - pattern: bleach.clean(...)
      - pattern: escape(...)
    message: >
      User input flows into SQL query without sanitization.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-89: SQL Injection"]
```

---

## Python Security Vulnerability Categories

### 1. SQL Injection (CWE-89)
**What to detect**: User input concatenated/interpolated into SQL queries.

**Key patterns**:
- f-string in execute: `cursor.execute(f"SELECT ... {$VAR} ...")`
- String concatenation: `cursor.execute("SELECT " + $VAR)`
- %-formatting: `cursor.execute("SELECT %s" % $VAR)`
- .format(): `cursor.execute("SELECT {}".format($VAR))`

**Safe alternatives** (should NOT trigger):
- Parameterized: `cursor.execute("SELECT ?", (param,))`
- ORM queries with proper escaping

---

### 2. Command Injection (CWE-78)
**What to detect**: User input passed to shell execution functions.

**Key sinks**:
- `os.system($CMD)`
- `os.popen($CMD)`
- `subprocess.call($CMD, shell=True)`
- `subprocess.Popen($CMD, shell=True)`
- `subprocess.run($CMD, shell=True)`
- `eval($EXPR)`
- `exec($CODE)`

**Safe alternatives**:
- `subprocess.run(["cmd", arg], shell=False)` (list form, no shell)
- `shlex.quote()` for escaping

---

### 3. Cross-Site Scripting / XSS (CWE-79)
**What to detect**: User input rendered in HTML without escaping.

**Key patterns**:
- `Markup($USER_INPUT)` (Flask)
- `mark_safe($USER_INPUT)` (Django)
- `|safe` filter in templates with user data
- `Response($USER_INPUT, content_type="text/html")`

---

### 4. Path Traversal (CWE-22)
**What to detect**: User input used in file paths without validation.

**Key sinks**:
- `open($USER_PATH, ...)`
- `os.path.join($BASE, $USER_INPUT)` without validation
- `pathlib.Path($USER_INPUT)`
- `shutil.copy($USER_INPUT, ...)`
- `send_file($USER_INPUT)`

---

### 5. Weak Cryptography (CWE-327)
**What to detect**: Use of deprecated/weak cryptographic algorithms.

**Key patterns**:
- `DES.new(...)`, `Blowfish.new(...)`, `RC4.new(...)`
- `AES.new($KEY, AES.MODE_ECB)` (ECB mode)
- Small key sizes: key length < 128 bits

---

### 6. Weak Hashing (CWE-328)
**What to detect**: Use of weak hash functions for security purposes.

**Key patterns**:
- `hashlib.md5(...)`
- `hashlib.sha1(...)`
- `MD5.new(...)`, `SHA.new(...)`

---

### 7. Weak Randomness (CWE-330)
**What to detect**: Use of predictable random for security-sensitive operations.

**Key patterns**:
- `random.random()`, `random.randint(...)` for tokens/keys/passwords
- Should use `secrets.token_hex()`, `secrets.token_urlsafe()`, `os.urandom()`

---

### 8. Insecure Deserialization (CWE-502)
**What to detect**: Deserializing untrusted data.

**Key patterns**:
- `pickle.loads($USER_DATA)`
- `pickle.load($USER_FILE)`
- `yaml.load($DATA)` without `Loader=SafeLoader`
- `marshal.loads($DATA)`
- `shelve.open($USER_PATH)`

---

### 9. LDAP Injection (CWE-90)
**What to detect**: User input in LDAP queries without escaping.

**Key patterns**:
- `ldap.search_s($BASE, $SCOPE, f"(uid={$USER_INPUT})")`
- String concatenation in LDAP filters

---

### 10. XPath Injection (CWE-643)
**What to detect**: User input in XPath expressions.

**Key patterns**:
- `tree.xpath(f"//{$USER_INPUT}")`
- `etree.XPath("//user[@name='" + $INPUT + "']")`

---

### 11. Insecure Cookie (CWE-614)
**What to detect**: Cookies set without secure flags.

**Key patterns**:
- `response.set_cookie($NAME, $VALUE)` without `secure=True`
- `response.set_cookie($NAME, $VALUE, httponly=False)`

---

### 12. Trust Boundary Violation (CWE-501)
**What to detect**: Mixing trusted and untrusted data in session.

**Key patterns**:
- `session[$KEY] = request.form[$INPUT]` (storing unvalidated user input in session)

---

### 13. Open Redirect (CWE-601)
**What to detect**: User input used directly in redirects.

**Key patterns**:
- `redirect(request.args.get("url"))`
- `redirect(request.form["next"])`

---

### 14. XXE - XML External Entity (CWE-611)
**What to detect**: XML parsing with external entities enabled.

**Key patterns**:
- `etree.parse($INPUT)` without disabling external entities
- `xml.sax.parseString($INPUT)` without secure configuration
- `pulldom.parseString($INPUT)`

---

## Rule Writing Best Practices

### 1. Minimize False Positives
- Use `pattern-not` to exclude safe patterns
- Use `pattern-inside` to scope to relevant contexts
- Use `metavariable-regex` to filter specific values
- Test against both vulnerable AND safe code

### 2. Maximize True Positives
- Cover all variants (f-strings, .format(), %, concatenation)
- Use `pattern-either` for multiple sink patterns
- Consider taint mode for data-flow vulnerabilities
- Account for variable aliasing: `cmd = user_input; os.system(cmd)`

### 3. Write Clear Messages
- State what was found
- Explain why it's dangerous
- Provide the secure alternative with code example
- Reference CWE and OWASP categories

### 4. Rule ID Conventions
- Format: `python-<category>-<specifics>`
- Examples: `python-sqli-fstring`, `python-cmdi-os-system`, `python-xss-markup-unsafe`

### 5. Use Appropriate Severity
- **ERROR**: Confirmed vulnerability (SQL injection with user input)
- **WARNING**: Likely vulnerable (weak hash usage, may be non-security context)
- **INFO**: Worth reviewing (audit finding, potential issue)

---

## Testing Against OWASP BenchmarkPython

### Setup
```bash
# Clone the benchmark (if not already present)
git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git benchmark/

# Run rules against benchmark
opengrep --config rules/python/ --json benchmark/testcode/ > output/results.json
```

### Benchmark Structure
- **1,230 test cases** across 14 vulnerability categories
- Each test case is intentionally vulnerable or intentionally safe
- Expected results in `benchmark/expectedresults-0.1.csv`
- Format: `test_name, category, CWE, is_vulnerable (true/false)`

### Scoring
```
TPR (True Positive Rate) = TP / (TP + FN)  — detection rate
FPR (False Positive Rate) = FP / (FP + TN) — false alarm rate
Score = TPR - FPR  (Youden Index)
```

**Target**: TPR > 80%, FPR < 20% per category. A "SUPER" rule achieves TPR > 90% with FPR < 10%.

### Scoring Workflow
1. Run opengrep with rules against `benchmark/testcode/`
2. Parse JSON output to get findings per test file
3. Compare against `expectedresults-0.1.csv`
4. Calculate TPR, FPR, and Youden Index per CWE category
5. Iterate: refine rules that have low TPR or high FPR

---

## Rule Development Workflow

### Phase 1: Analyze
1. Pick a CWE category (e.g., CWE-89 SQL Injection)
2. Read BenchmarkPython test cases for that category
3. Identify the vulnerable patterns vs. safe patterns
4. Note the specific Python APIs and code constructs used

### Phase 2: Design
1. Draft rule patterns that catch the vulnerable constructs
2. Add `pattern-not` exclusions for safe patterns
3. Consider whether taint mode would improve accuracy
4. Write a clear, actionable message

### Phase 3: Test
1. Run the rule against the benchmark
2. Check results: which test cases hit, which missed?
3. Calculate TPR and FPR for this rule

### Phase 4: Refine
1. For missed true positives: broaden patterns or add `pattern-either` variants
2. For false positives: add `pattern-not` or `pattern-not-inside` exclusions
3. Re-test and iterate until scores meet targets

### Phase 5: Document
1. Add metadata (CWE, OWASP, confidence, impact)
2. Ensure message has remediation guidance
3. Save rule to `rules/python/<cwe-category>/`

---

## Directory Structure

```
opengrep-rule-agent/
├── .github/
│   ├── skills/
│   │   └── opengrep/
│   │       └── SKILL.md          # This file
│   └── agents/
│       ├── rule-creator.agent.md  # Main rule creation agent
│       ├── rule-analyzer.agent.md # Analyzes benchmark code patterns
│       └── rule-tester.agent.md   # Tests and scores rules
├── rules/
│   └── python/
│       ├── sqli/                  # SQL Injection rules
│       ├── cmdi/                  # Command Injection rules
│       ├── xss/                   # XSS rules
│       ├── path-traversal/        # Path Traversal rules
│       ├── weak-crypto/           # Weak Cryptography rules
│       ├── weak-hash/             # Weak Hashing rules
│       ├── weak-random/           # Weak Randomness rules
│       ├── deserialization/       # Insecure Deserialization rules
│       ├── ldap-injection/        # LDAP Injection rules
│       ├── xpath-injection/       # XPath Injection rules
│       ├── insecure-cookie/       # Insecure Cookie rules
│       ├── trust-boundary/        # Trust Boundary Violation rules
│       ├── open-redirect/         # Open Redirect rules
│       └── xxe/                   # XXE rules
├── benchmark/                     # OWASP BenchmarkPython (cloned)
├── output/                        # Scan results and scores
├── scripts/
│   ├── run_scan.py               # Run opengrep against benchmark
│   └── score.py                  # Score results against expected
├── CLAUDE.md                      # Claude Code project instructions
└── README.md
```
