# Evaluation Plan: from Working Prototype to Reproducible Study

## What has actually been tested

The repository includes automated offline tests for:

- condition/schema/source quote validation;
- explicit missing-condition detection;
- bounded CREATE/VERIFY/REPAIR loop with mocked LLM providers;
- two target directories with identical plugin version and different configuration context;
- UNKNOWN handling when context is absent;
- integrity tampering rejection;
- refusal to run demo-only artifacts without explicit opt-in;
- failure on unsupported/incomplete evidence.

Run:

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
```

These tests validate the *implementation mechanics*. They do **not** measure production LLM extraction accuracy, the accuracy of WordPress database-state discovery, or forensic exploitation detection.

## Proposed evaluation dimensions

### 1. Extraction quality

Use a manually annotated, provenance-linked benchmark covering multiple CVEs and condition structures. Metrics:

- affected-version extraction precision / recall;
- feature/module prerequisite precision / recall;
- authentication prerequisite accuracy;
- logic-group fidelity (AND vs OR);
- evidence quotation validity;
- unsupported claim rate;
- omitted prerequisite rate.

### 2. Verification effectiveness

Inject errors into ground-truth candidate Skills:

- remove a required module condition;
- change an affected version upper bound;
- invent an authentication prerequisite;
- reverse an AND/OR relation;
- provide a false source attribution.

Measure detection recall, false rejection, repair success, number of iterations and rate of unsafe approvals. Keep a separate measurement for insufficient-evidence outcomes.

### 3. Local investigation

Test paired environments with equal affected versions but different configuration or exposure state. Measure:

- applicability decision accuracy;
- false-positive and false-negative rates;
- UNKNOWN/INCONCLUSIVE handling;
- evidence completeness;
- execution time and read-only compliance.

### 4. Ecosystem breadth

WordPress examples make a compact live demo, not a scope restriction. Future benchmarks should include server-side frameworks, CI/CD systems, database products, optional modules, authentication-specific vulnerabilities, and network exposure prerequisites. Target at least 20-30 annotated CVEs before drawing generalized accuracy conclusions.

## Reproducibility

Each evaluation run should record:

- CVE ID and exact record revision;
- source URLs, source timestamps and snapshot hashes;
- LLM provider/model identifier, version if supplied, temperature/configuration;
- candidate and verified Applicability Models;
- the entire repair history;
- local fixture version/configuration evidence;
- expected results and observed results;
- whether independent source families share an upstream CNA.

Do not fabricate benchmark percentages or label the small offline demonstration as a real-world measurement. Contributions of carefully labeled evaluation cases are welcome.
