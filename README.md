# Vuln-Skill

**From a CVE to a verified investigation Skill.**

> **An affected version does not always mean an applicable vulnerability.**

CVE scanners can tell you *what might be affected*. Vuln-Skill helps investigate *whether the vulnerability's required conditions are present*.

During the response to [Rails CVE-2026-66066 (KindaRails2Shell)](https://github.com/rails/rails-forensics-CVE-2026-66066), the Rails team published Agent Skills for **"Was I vulnerable?"** and **"Was I exploited?"** That is a compelling direction for vulnerability response: investigation procedures, not only advisories. But vendors cannot write a Skill for every CVE.

**Vuln-Skill explores how to generate those investigation procedures from public advisories, verify them, and safely reuse them.**

## The three commands

```console
$ vuln-skill create CVE-2026-82901
$ vuln-skill check generated/CVE-2026-82901.skill
$ vuln-skill investigate generated/CVE-2026-82901.skill ./my-target --context ./context.json
```

`create` includes `check` and an automatic, bounded repair loop. `check` is also available for re-verification later.

```text
Public CVE / CNA / advisory / patch
               |
               v
       CREATE  (OpenAI API)
               |
          Applicability Model
         (declarative JSON)
               |
          Candidate Skill
               |
       VERIFY (fresh sources + typed judgments)
          |                      ^
          | fail                 | feedback
          +-----------------> REPAIR   (up to 3 attempts)
          |
          | VERIFIED
          v
       INVESTIGATE (local, read-only, NO LLM API)
               |
     condition-by-condition evidence
               |
     NOT_APPLICABLE / APPLICABLE / EXPOSED / INCONCLUSIVE
```

**Fail closed:** unverified Skills cannot inspect a target, and changes to a verified Skill invalidate its integrity check. `VERIFIED` means the automated verification policy passed; it is **not** a guarantee of exploitability or absolute truth.

## Try it in 2 minutes — no API key needed

The **fully reproducible demo** runs offline with a clearly labeled, *illustrative evidence fixture*. It shows an initially incomplete Skill, verification failure, the missing condition, a repair, and two different investigation outcomes from the **same installed version**.

Requirements: Python 3.10+ and GitHub source checkout. **Windows shortcut:** double-click `scripts/run_demo_windows.bat` (it installs dependencies and runs the CVE-2026-85984 demo). See [Windows setup](docs/QUICKSTART.md) for PowerShell instructions.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e .
vuln-skill demo
# For the four-setting AND scenario used in our Arsenal CFP:
vuln-skill demo --cve CVE-2026-85984
```

Illustrative output (note the status is **DEMO_ONLY**, not VERIFIED):

```text
DEMO ONLY: bundled evidence excerpts and user-attested settings
[1/2] CREATE: version-only candidate (intentionally incomplete)
[1/2] VERIFY: NEEDS_REVIEW
        MISSING_CONDITION: PDF Generator module must be enabled
[2/2] REPAIR: add the missing PDF Generator prerequisite
[2/2] VERIFY: DEMO_ONLY (passed fixture checks; NOT live-verified)
[INVESTIGATE] site-enabled: APPLICABLE
[INVESTIGATE] site-disabled: NOT_APPLICABLE
```

The default demo uses CVE-2026-82901 (version plus an optional module). The alternate `--cve CVE-2026-85984` demo exercises a four-setting AND predicate, as described in the CFP. Both are illustrative only.

Both default fixtures contain a harmless WordPress-like plugin version header for version `3.5.49`. The module's enabled/disabled state is provided in an **operator-supplied example JSON context**; the demo does *not* inspect a production WordPress database. This is a workflow demonstration, **not** a live vulnerability verification.

Generated demo files are written to `demo-output/CVE-2026-82901.skill`. For manual inspection:

```bash
vuln-skill investigate demo-output/CVE-2026-82901.skill \
  examples/targets/site-enabled \
  --context examples/targets/site-enabled/context.json --allow-demo
```

The `--allow-demo` opt-in is required for `DEMO_ONLY` fixtures. It never upgrades them to VERIFIED.

## Real CVEs with the OpenAI API

`create` and `check` use public data from the [CVE List / CNA API](https://cveawg.mitre.org/api/), GitHub advisory API and selected public reference hosts. Extraction and verification use the official [OpenAI Python SDK Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs).

```bash
# Configure an API key using your shell's secret-management mechanism.
export OPENAI_API_KEY="YOUR_API_KEY"      # PowerShell: $env:OPENAI_API_KEY="YOUR_API_KEY"
export VULN_SKILL_MODEL="gpt-4.1-mini"    # Optional
export VULN_SKILL_VERIFY_MODEL="gpt-4.1-mini"  # Optional; can differ from extractor

vuln-skill create CVE-2026-82901 --max-attempts 3
vuln-skill check generated/CVE-2026-82901.skill
vuln-skill investigate generated/CVE-2026-82901.skill ./wordpress --context ./my-context.json
```

**Important:** source availability varies. GitHub rate limits, inaccessible vendor pages, contradictory disclosures, or incomplete product-specific probes may result in `NEEDS_REVIEW` or `INCONCLUSIVE`. Those are correct fail-closed outcomes, not reasons to force a VERIFIED badge. The real API workflow requires your own API key and network access; end-to-end live verification is not claimed merely because offline tests pass.

## Why WordPress in the example?

**For simplicity, not because Vuln-Skill is WordPress-specific.** WordPress plugin advisories often state a version range **plus** a module/setting prerequisite, which makes applicability easy to explain in a short Arsenal demo. The public information → JSON model → independent verification → local investigation architecture is ecosystem-agnostic. This first prototype offers a WordPress plugin-version probe, safe file probes and explicit JSON-context probes; deeper adapters for other ecosystems are planned.

## What CREATE actually builds

A Skill is a directory (named `CVE-....skill`, not a special executable binary):

```text
CVE-2026-82901.skill/
├── SKILL.md             # human/agent-readable guidance
├── applicability.json   # typed conditions + AND-of-OR logic
├── verification.json    # verdict, decisions, sources, integrity hashes
├── sources.json         # retrieved evidence and timestamps
├── manifest.json        # provenance + verification status
├── attempts.json        # repair-loop history
└── agents/
    └── openai.yaml      # ChatGPT-compatible UI metadata
```

The intermediate **Applicability Model** is *JSON*, not free-form generated code. A condition may be `Version <= 3.5.50` AND `PDF Generator enabled`; it can be supported by source evidence even when its configuration value cannot be automatically read. In the latter case the investigator reports `UNKNOWN` unless the operator supplies an explicit context file. **Unknown never becomes false or safe.**

## What VERIFY checks

1. **Structural:** schema, condition IDs, AND/OR groups, provenance references, declared safe probes.
2. **Evidence:** fresh fetching of public documents, verbatim citation matching, at least two separately retrieved source families.
3. **Semantic:** constrained LLM decisions (`SUPPORTED`, `CONTRADICTED`, `INSUFFICIENT_EVIDENCE`) plus a search for **omitted prerequisites**.
4. **Repair:** incorrect or missing prerequisites become feedback for regeneration; maximum three attempts by default.
5. **Gate:** only live `VERIFIED` results are accepted by `investigate`; SHA-256 binds the verdict to the JSON model and generated `SKILL.md`.

**Verification is a research prototype, not a formal proof.** Different sources may repeat the same CNA disclosure, and typed LLM output does not guarantee semantic correctness. If reliable evidence is not available, status remains `NEEDS_REVIEW`.

## What INVESTIGATE does **not** do

- It does **not** exploit vulnerabilities, send network probes, install or execute LLM-generated code, or modify a target.
- It does **not** upload private source code, configurations, credentials or logs to OpenAI during investigation.
- It does **not** infer that an absence of attack indicators proves an environment was never exploited.
- It does **not** claim to inspect arbitrary WordPress database settings without a site-specific adapter; normalized context JSON is explicitly supplied by the operator.
- It does **not** yet implement a production-grade forensic exploitation detector or automatically produce `EVIDENCE_OF_EXPLOITATION`. Those are future capabilities, not current test results.

## Documentation for reviewers

| Document | What it explains |
| --- | --- |
| [Reviewer one-pager](docs/REVIEWER_ONE_PAGER.md) | What it solves, live commands, reproducible demo, and current maturity |
| [Quick start](docs/QUICKSTART.md) | Install, demo and live API commands on Windows/Linux/macOS |
| [Architecture](docs/ARCHITECTURE.md) | Threat model, data flow, JSON schema and verification gate |
| [Arsenal demonstration](docs/ARSENAL_DEMO.md) | Five-minute demo script and expected results |
| [Evidence and limitations](docs/VERIFICATION_POLICY.md) | Meaning of VERIFIED, uncertainty and security restrictions |
| [Evaluation](docs/EVALUATION.md) | Reproducible tests and planned larger CVE benchmarks |
| [GitHub publishing](docs/PUBLISH_TO_GITHUB.md) | Upload this repo with GitHub CLI or Git |
| [Security](SECURITY.md) | Threat model, responsible use and vulnerability reporting |

## Development / tests

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
```

Tests use mocked providers and local fixtures. No network or paid API calls are required. GitHub Actions runs the same test suite on every push or pull request.

## Project status and next milestones

**v0.1.0: research prototype / Arsenal CFP submission.** Implemented: public CVE/GHSA collection, OpenAI structured extraction, evidence-gated verification with bounded repairs, SHA-bound Skill artifacts, read-only local probes, test fixtures, CI, and an API-free demo. Current support is intentionally narrower than the long-term vision. Planned: more ecosystem adapters, actual WordPress configuration/database adapters, forensic checks, stronger evidence independence, calibrated typed decision backends (including Jev-like models), benchmark results and signed Skill distribution.

**Generate once. Verify it. Investigate anywhere.**

## License

Apache-2.0. See [LICENSE](LICENSE). Developed as an independent, open-source security research project. No vendor endorsement is implied.
