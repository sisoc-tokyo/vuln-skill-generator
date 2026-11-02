# Architecture and threat model

## Why this exists

A vulnerable product/version pair is a *candidate*, not the complete applicability predicate. A vulnerability can require several simultaneously enabled features, an optional module, an authentication state, or a reachable component. Critical qualifiers are often recorded only as natural language. Vuln-Skill captures these as evidence-backed predicates rather than replacing technical assessment with a single conversational LLM answer.

## Pipeline

```text
                          Public sources
                       CVE / CNA / GHSA
                        trusted references
                                |
                          [ Collector ]
                                |
               [ OpenAI Structured Extraction ]
                                |
                        ApplicabilityModel
                                |
                   [ Deterministic Compiler ]
                                |
                        candidate .skill
                                |
                fresh public evidence collection
                                |
                   [ Structured Verifier ]
                   |                  |
               rejected             pass
                   |                  |
                feedback          VERIFIED
                   |                  |
             [ Repair ]         content hashes
                   |                  |
            <= 3 attempts            v
                   +---         [ INVESTIGATE ]
                                       |
                            read-only local checks
                                       |
                              evidence + status
```

## Applicability Model v0.1

`src/vuln_skill/models.py` is the canonical Pydantic schema. There is no second handwritten schema that can drift from the implementation. Example (simplified):

```json
{
  "cve_id": "CVE-2026-82901",
  "product": "Ultra Addons for Contact Form 7",
  "ecosystem": "wordpress",
  "plugin_slug": "ultimate-addons-for-contact-form-7",
  "summary": "An optional module is required.",
  "conditions": [
    {
      "id": "affected_version",
      "category": "version",
      "description": "Version <= 3.5.50",
      "comparison": "lte",
      "expected": "3.5.50",
      "evidence_source_id": "CVE-CNA",
      "evidence_quote": "in all versions up to, and including, 3.5.50",
      "probe_kind": "wordpress_version",
      "probe_path": "wp-content/plugins/ultimate-addons-for-contact-form-7",
      "probe_key": ""
    },
    {
      "id": "pdf_module_enabled",
      "category": "module",
      "description": "PDF Generator must be enabled",
      "comparison": "eq",
      "expected": "true",
      "evidence_source_id": "GHSA-1",
      "evidence_quote": "only exploitable when the plugin's PDF Generator module is enabled",
      "probe_kind": "context_value",
      "probe_path": "",
      "probe_key": "settings.pdf_generator_enabled"
    }
  ],
  "groups": [
    {"any_of": ["affected_version"]},
    {"any_of": ["pdf_module_enabled"]}
  ]
}
```

The overall applicability predicate is **AND of groups**; each group's `any_of` items are joined by OR. This canonical conjunctive normal form expresses ordinary AND chains and combinations of OR alternatives. Negation of observations can be represented by `ne` or `absent` predicates where grounded by source evidence.

## Trust boundaries

| Component | Allowed input | Never allowed |
| --- | --- | --- |
| Collector | Public CVE/advisory web endpoints | User's private repositories or target filesystem |
| Extractor LLM | Public source text and previous candidate feedback | Target configs, logs, private SBOM or credentials |
| Verifier LLM | Fresh public text, generated applicability model | Target filesystem or credentials |
| Compiler | Validated JSON | Arbitrary LLM-provided executable scripts |
| Investigator | Verified, content-hash-bound Skill and local files | Network requests, LLM API calls, shell execution, target writes |

The collector restricts outgoing URLs to trusted public HTTPS hosts and disables redirects. This helps reduce unexpected requests but is not a substitute for complete isolation against malicious third-party sites or DNS rebinding. Use network isolation in high-assurance deployments.

## Local probe types

| Probe | Status | Description |
| --- | --- | --- |
| `wordpress_version` | Implemented | Read a plugin version from a local WordPress-style PHP header |
| `context_value` | Implemented | Read an explicit key from user-supplied JSON; *not* inferred WordPress DB state |
| `file_exists` | Implemented | Confirm a regular file exists in the target root |
| `file_contains` | Implemented | Bounded, read-only text predicate on an explicitly declared file |
| `manual` | Implemented | Return UNKNOWN (never silently assume a value) |
| Native WordPress DB adapter | Not implemented | Not included in v0.1 |
| Active network probing | Not implemented | No network traffic from investigator |
| Proven exploitation detector | Not implemented | No automatic `EVIDENCE_OF_EXPLOITATION` output |

The local investigator blocks path traversal and symlink reads, has file-size limits, and never performs `exec`, `subprocess`, `eval`, or network requests. It can read targets only when explicitly invoked with a directory path by the operator.

## Verification and state machine

- New candidate: untrusted, not investigatable.
- All structural/evidence/semantic checks pass: live `VERIFIED`.
- Missing prerequisite, unsupported claim, missing source or source insufficiency: `NEEDS_REVIEW`.
- Bundled illustrative demo: `DEMO_ONLY` even if its mock judgment passes.
- Changed `applicability.json` or `SKILL.md`: invalid content integrity; refuse investigation until reverified.
- Stale verification (default >30 days): refuse by default.

`verification.json` and `manifest.json` record status. The investigator reads `verification.json`, checks its content hashes, and does not trust the more human-friendly `SKILL.md` as executable code.

## Limitations and intended evolution

The verification model is still probabilistic and could overlook a prerequisite or misinterpret a source. Two public outlets may repeat the same upstream disclosure. Hashes detect accidental edits, not forged verification reports (digital signing is future work). An operator-supplied context key reflects the operator's information, not a database probe. `VERIFIED` therefore means the *implemented evidence policy* passed, **not** formal, exhaustive proof that the generated investigation is correct. High-impact results require expert review and additional measurements.
