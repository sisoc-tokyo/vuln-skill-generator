# Black Hat Arsenal — Five-Minute Demonstration

## 00:00 — The problem

**An affected version is not always an applicable vulnerability.**

In the Rails CVE-2026-66066 response, Agent Skills showed how a vendor could publish executable investigation knowledge alongside an advisory. Vuln-Skill asks: *what if those procedures could be generated and verified for many CVEs?*

## 00:40 — The reproducible offline walkthrough

Run from the GitHub source checkout:

```bash
vuln-skill demo --cve CVE-2026-85984
```

The command uses *illustrative bundled evidence* for CVE-2026-85984, a WordPress plugin case with an affected version (up to 5.5.5) and **four simultaneously required login settings**. Alternatively, `vuln-skill demo` shows CVE-2026-82901 with an optional PDF Generator prerequisite.

WordPress is chosen for short, reproducible demonstration logic. **The architecture is not WordPress-specific.**

## 01:20 — An incomplete Skill is rejected

The first candidate has only the version predicate. The fixture verifier identifies **four missing configuration conditions** (one shown here):

```text
[1/2] VERIFY: NEEDS_REVIEW
MISSING_CONDITION: Admin OTP Bypass must be enabled
```

This exposes the key failure mode: an LLM can generate a plausible Skill while omitting an essential prerequisite.

## 02:00 — Evidence-based repair

The demo repairs the model by adding the four missing settings, then verifies it against fixture evidence. **The result is `DEMO_ONLY`, never `VERIFIED`, because cached mock evidence is not live verification.**

```text
[2/2] VERIFY: DEMO_ONLY (fixture checked; NOT authoritative verification)
```

For the actual API-backed workflow, demonstrate on a networked machine with `OPENAI_API_KEY` configured:

```bash
vuln-skill create CVE-2026-85984 --max-attempts 3
```

Outcomes can be `VERIFIED` or `NEEDS_REVIEW` depending on available evidence. Do not fake a successful live result.

## 03:00 — Same version, different reality

The offline fixtures have the **same** WordPress-style plugin version header (`5.5.5`). Their explicitly supplied context differs:

```json
{"settings":{"wp_login_otp":true,"login_only_otp":true,"username_password_allowed":true,"admin_otp_bypass":true}}
```

versus:

```json
{"settings":{"wp_login_otp":true,"login_only_otp":true,"username_password_allowed":true,"admin_otp_bypass":false}}
```

The demo outputs:

```text
[INVESTIGATE] otp-all-enabled: APPLICABLE
[INVESTIGATE] otp-bypass-disabled: NOT_APPLICABLE
```

This difference is derived from the **declared evidence in the synthetic fixture**, not a discovered vulnerability in a production system.

## 04:00 — Show the auditable artifact

Open:

```text
demo-output/CVE-2026-85984.skill/applicability.json
demo-output/CVE-2026-85984.skill/verification.json
demo-output/CVE-2026-85984.skill/SKILL.md
demo-output/CVE-2026-85984.skill/attempts.json
```

Explain that the declarative JSON is the machine-readable source of truth, while `SKILL.md` is readable documentation. Runtime investigation is performed by deterministic, read-only probes.

## 04:40 — The take-away

**Stop matching CVEs. Start testing applicability.**

A verified Skill can be used repeatedly against different authorized environments. The LLM extracts evidence-backed investigation logic; the local investigator evaluates facts. Unverified candidates never receive permission to examine the target environment.

### Questions the reviewer may ask

**Is this a WordPress scanner?** No. WordPress is a demo ecosystem; the architecture applies beyond it. v0.1 has only a few local probe adapters and is deliberately upfront about the current limitation.

**Does VERIFIED guarantee correctness?** No. It means the implemented automated, evidence-based policy passed. This tool should augment analyst review, not replace it.

**Can it run without an OpenAI API key?** Yes for the `demo` fixture and deterministic tests. Live `create` and `check` require a key and public internet.

**Does it upload my site's configurations to an LLM?** No; only public advisory information goes through the API. Target-side `investigate` performs no HTTP or LLM calls.

**What about never-exploited claims?** Absence of indicators is not proof of no exploitation. The current version reports applicability; a robust exploitation-evidence engine remains future work.
