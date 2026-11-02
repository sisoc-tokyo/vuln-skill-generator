# Vuln-Skill — Arsenal Reviewer's One-Pager

## What is the problem?

**Most vulnerability alerts say "affected version." That is not the same as "applicable vulnerability."** A real CVE may additionally require a feature to be enabled, several options to be set together, a component to be reachable, or an optional module to be installed. Those prerequisites often live in unstructured advisories and patch notes rather than machine-readable scanning metadata.

The Rails team's Agent Skills for [CVE-2026-66066](https://github.com/rails/rails-forensics-CVE-2026-66066) illustrated an important direction: an advisory can come with an investigation procedure. **But what happens when the vendor does not publish that Skill?**

## The tool in one minute

```bash
vuln-skill create CVE-2026-85984
vuln-skill check generated/CVE-2026-85984.skill
vuln-skill investigate generated/CVE-2026-85984.skill ./target --context ./context.json
```

- **CREATE** extracts machine-readable applicability conditions from public information using a generative LLM.
- **VERIFY** checks every condition against freshly retrieved evidence, looks for *missing* prerequisites, and regenerates a candidate if something is wrong. Retries are bounded.
- **INVESTIGATE** reads a VERIFIED artifact and executes deterministic, read-only checks against local evidence. Sensitive local data is not sent to the generation API.

The key boundary is **no unverified Skill reaches the target environment**.

## Try the demo now, without API credentials

```bash
python -m pip install -e .
vuln-skill demo --cve CVE-2026-85984
```

The demo intentionally starts with only a version condition, then identifies four missing login settings described in the public advisory. It shows a repair, followed by two synthetic WordPress-like target directories containing **the same plugin version** and different operator-supplied setting states. One yields `APPLICABLE`; the other `NOT_APPLICABLE`.

**Transparency:** this is an illustrative offline fixture and ends in `DEMO_ONLY`. It is not passed off as a live third-party verification. The real API-backed path uses OpenAI Structured Outputs plus freshly retrieved public sources and may correctly end in `NEEDS_REVIEW` if the evidence is incomplete.

## Why WordPress?

Because it makes a complex applicability question understandable in a five-minute demo. **Vuln-Skill is not a WordPress-specific design.** Its intermediate model, verification gate and local-execution boundary are portable across ecosystems; deeper adapters remain future work.

## What is different from an LLM wrapper?

The LLM is **not** asked for a final verdict on the user's system. It extracts candidate predicates from public text. The verifier treats the generated artifact as untrusted, requires exact textual evidence, challenges omissions, and blocks anything that cannot pass. The investigator works from explicit, locally observable evidence; unknown facts remain `INCONCLUSIVE`.

**CVE matching tells you what might be vulnerable. Vuln-Skill helps establish which conditions actually hold.**

## Maturity and limitations

This is a v0.1 research prototype with an API-free, testable local demo and a real OpenAI SDK integration. A full production benchmark, WordPress database adapter, exploit-evidence engine, verified signing, and formal proof of complete coverage are not implemented. The repository documents these limitations explicitly and includes reproducible tests and CI rather than invented evaluation numbers.

**Start with:** [README](../README.md), [Demo Script](ARSENAL_DEMO.md), [Verification Policy](VERIFICATION_POLICY.md).
