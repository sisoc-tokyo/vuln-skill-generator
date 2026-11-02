# Quick Start — Vuln-Skill

This guide intentionally separates the **offline demo** from **live API-backed generation**.

## Prerequisites

- Python 3.10 or newer
- A terminal (PowerShell, Terminal, Bash)
- Internet only for installing dependencies and running live `create` / `check`
- OpenAI API key only for live `create` / `check`

## 1. Install on Windows (PowerShell)

In the unzipped repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
vuln-skill --help
```

If PowerShell execution policy blocks activation, use `.\.venv\Scripts\python.exe -m pip install -e .` and `.\.venv\Scripts\vuln-skill.exe demo` without changing system policy.

## 2. Install on Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
vuln-skill --help
```

## 3. Reproducible API-free demo

```bash
vuln-skill demo
# Also try the four-setting example from the Arsenal CFP:
vuln-skill demo --cve CVE-2026-85984
```

The offline demo:

1. Creates a deliberately incomplete version-only model for `CVE-2026-82901`.
2. Detects that a required PDF Generator module condition is missing.
3. Repairs the *demo fixture* model.
4. Marks the output `DEMO_ONLY`, never `VERIFIED`.
5. Evaluates two harmless local examples with exactly the same plugin version (`3.5.49`).
6. Returns `APPLICABLE` when an operator-provided example context says the module is enabled and `NOT_APPLICABLE` when it says disabled.

This simulates the decision pipeline for teaching and review. **It does not perform real CVE verification, automatic WordPress configuration discovery, or exploit validation.**

## 4. Use the OpenAI API for real source processing

Windows PowerShell:

```powershell
$env:OPENAI_API_KEY = "YOUR_REAL_API_KEY"
$env:VULN_SKILL_MODEL = "gpt-4.1-mini"
$env:VULN_SKILL_VERIFY_MODEL = "gpt-4.1-mini"
vuln-skill create CVE-2026-82901
```

Linux/macOS:

```bash
export OPENAI_API_KEY="YOUR_REAL_API_KEY"
vuln-skill create CVE-2026-82901
```

The `create` command fetches public advisories, extracts JSON with OpenAI Structured Outputs, then independently asks the verifier to test the claims against fresh evidence. If necessary it retries up to three times. Valid final results are written under `generated/CVE-2026-82901.skill/`.

Inspect `verification.json` and `attempts.json`. If status is `NEEDS_REVIEW`, investigate will correctly refuse.

## 5. Recheck independently

```bash
vuln-skill check generated/CVE-2026-82901.skill
```

This requires API key and public internet again; it does not simply trust an old `verification.json`.

## 6. Investigate locally

```bash
vuln-skill investigate generated/CVE-2026-82901.skill ./my-wordpress --context ./my-context.json
```

Example *operator-attested* context (not a WordPress option-name assertion):

```json
{
  "settings": {
    "pdf_generator_enabled": true
  }
}
```

If this key is not provided and the generated Skill requires it, the result is `INCONCLUSIVE` rather than an invented answer.

To capture structured evidence:

```bash
vuln-skill investigate generated/CVE-2026-82901.skill ./my-wordpress \
  --context ./my-context.json --json report.json
```

On Windows PowerShell place all parameters on one line (or use PowerShell backticks).

## 7. Running tests without paying for API calls

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
```

## 8. Troubleshooting

| Symptom | Meaning / remediation |
| --- | --- |
| `OPENAI_API_KEY is missing` | API-backed workflow requires a key; `demo` does not |
| `NEEDS_REVIEW` | Verification could not prove all required claims; read `verification.json` |
| `SOURCE_DIVERSITY` | Too few separately retrieved source families; do not force success |
| `INCONCLUSIVE` | Required local fact is unknown; supply valid context or an adapter |
| `Skill contents changed` | Content hash no longer matches; run `check` again |
| `Skill verification is stale` | Re-run `check`; default maximum age is 30 days |
| GHSA 403 / vendor page missing | Source rate limit or blocking; collector logs a warning and fails closed if necessary |

## Handling secrets

Set `OPENAI_API_KEY` in environment variables or a secure secrets manager. Do not commit it, include it in screenshots, or paste it into GitHub issues. `.env` is ignored but `.env.example` contains only placeholders. Never place organization-private investigation material in public advisory files.
