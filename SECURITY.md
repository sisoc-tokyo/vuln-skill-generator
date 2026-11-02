# Security Policy

Vuln-Skill is a **defensive research prototype**, not a general-purpose penetration testing framework or a substitute for incident response expertise.

## Supported use

Use it only with public CVE materials and on systems or local artifact directories that you own or are authorized to investigate. `investigate` runs read-only checks and does not generate exploit payloads, execute generated shell commands, or send local data to an LLM. A `VERIFIED` status is evidence-policy verification of the Skill candidate, not a guarantee of security or safety.

## Reporting vulnerabilities in Vuln-Skill

Do not post exploitable vulnerabilities in public issues. Use GitHub's private vulnerability reporting feature if enabled on the repository, or contact the repository maintainer through their published professional contact channel. A response SLA is not guaranteed for this research prototype.

## Security controls / caveats

- API keys come from process environment variables.
- Public advisory retrieval uses HTTPS, no redirects, size/time limits and allowed host names.
- No arbitrary generated script execution.
- Local file reads are target-relative; path traversal and symlinks are rejected.
- Verification binds an artifact to `applicability.json` and `SKILL.md` with SHA-256 checksums.
- Checksums alone do not authenticate authors; signed artifacts are future work.
- Context JSON is a **user assertion** and must be audited separately.
- A language model is fallible even when output shape is constrained.

## Known limitations

There is no native WordPress DB connector, no evidence-backed exploit confirmation, no hardened sandbox, no signed provenance, and no formal proof of completeness. The LIVE API path requires trusted network access to OpenAI and official disclosure sources, with operational error handling rather than security guarantees.
