"""Clearly labeled, API-free walkthrough using illustrative cached evidence.

Not a substitute for live verification. Never marks demo artifacts VERIFIED.
"""
from __future__ import annotations

from pathlib import Path

from .compiler import write_skill
from .investigation import investigate
from .models import (ApplicabilityModel, Condition, ConditionGroup, Decision,
                     MissingCondition, SourceRecord, VerificationJudgment, utc_now)
from .verification import build_report


CVE_ID = "CVE-2026-82901"
VERSION_QUOTE = "in all versions up to, and including, 3.5.50"
MODULE_QUOTE = "only exploitable when the plugin's PDF Generator module is enabled"
SAMPLE_TEXT = (
    "The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to "
    "Arbitrary File Upload due to insufficient file type validation in the "
    "'uacf7_wpcf7_mail_components' function in all versions up to, and including, 3.5.50. "
    "This makes it possible for unauthenticated attackers to upload arbitrary files. "
    "Note: This is only exploitable when the plugin's PDF Generator module is enabled, "
    "which is disabled by default. "
    "Reference: https://plugins.trac.wordpress.org/browser/ultimate-addons-for-contact-form-7/"
)


def _sources() -> list[SourceRecord]:
    # The extracts below illustrate publicly documented CVE facts, but are snapshots
    # bundled with this tool and NOT fetched independently in the demo.
    return [
        SourceRecord(id="CVE-CNA", title="Demonstration extract (CNA-style, cached)",
                     url="https://cveawg.mitre.org/api/cve/CVE-2026-82901",
                     authority="CVE/CNA", text=SAMPLE_TEXT, fetched_at=utc_now()),
        SourceRecord(id="GHSA-1", title="Demonstration extract (GHSA-style, cached)",
                     url="https://github.com/advisories/GHSA-m2gh-25xj-89p6",
                     authority="GHSA", text=SAMPLE_TEXT, fetched_at=utc_now()),
    ]


def _model(include_module: bool) -> ApplicabilityModel:
    conditions = [Condition(
        id="affected_version", category="version", description="Ultra Addons <= 3.5.50",
        comparison="lte", expected="3.5.50", evidence_source_id="CVE-CNA",
        evidence_quote=VERSION_QUOTE, probe_kind="wordpress_version",
        probe_path="wp-content/plugins/ultimate-addons-for-contact-form-7", probe_key="")]
    groups = [ConditionGroup(any_of=["affected_version"])]
    if include_module:
        conditions.append(Condition(
            id="pdf_module_enabled", category="module", description="PDF Generator module must be enabled",
            comparison="eq", expected="true", evidence_source_id="GHSA-1",
            evidence_quote=MODULE_QUOTE, probe_kind="context_value", probe_path="",
            probe_key="settings.pdf_generator_enabled"))
        groups.append(ConditionGroup(any_of=["pdf_module_enabled"]))
    return ApplicabilityModel(cve_id=CVE_ID, product="Ultra Addons for Contact Form 7",
                              ecosystem="wordpress", plugin_slug="ultimate-addons-for-contact-form-7",
                              summary="Arbitrary file upload; requires PDF Generator enabled.",
                              conditions=conditions, groups=groups)


def _judgment(include_module: bool) -> VerificationJudgment:
    decisions = [Decision(condition_id="affected_version", verdict="SUPPORTED",
                          evidence_source_id="GHSA-1", evidence_quote=VERSION_QUOTE,
                          reason="An affected version range is explicitly stated")]
    missing = []
    if include_module:
        decisions.append(Decision(condition_id="pdf_module_enabled", verdict="SUPPORTED",
                                  evidence_source_id="CVE-CNA", evidence_quote=MODULE_QUOTE,
                                  reason="Optional feature prerequisite is explicitly stated"))
    else:
        missing.append(MissingCondition(description="PDF Generator module must be enabled",
                                        evidence_source_id="GHSA-1", evidence_quote=MODULE_QUOTE))
    return VerificationJudgment(decisions=decisions, missing_conditions=missing)


def run_demo(output: Path, *, examples: Path) -> Path:
    sources = _sources()
    print("DEMO ONLY: bundled evidence excerpts and user-attested settings; no API key or network")
    print("[1/2] CREATE: version-only candidate (intentionally incomplete)")
    first = _model(include_module=False)
    first_report = build_report(first, sources, _judgment(False), mode="demo", attempts=1)
    print(f"[1/2] VERIFY: {first_report.status}")
    for issue in first_report.issues:
        print(f"        {issue.kind}: {issue.description}")
    print("[2/2] REPAIR: add the missing PDF Generator prerequisite")
    second = _model(include_module=True)
    last_report = build_report(second, sources, _judgment(True), mode="demo", attempts=2)
    if last_report.status != "DEMO_ONLY":
        raise RuntimeError(f"Demo verification failed unexpectedly: {last_report.issues}")
    print("[2/2] VERIFY: DEMO_ONLY (passed fixture checks; NOT live-verified)")
    path = output / f"{CVE_ID}.skill"
    write_skill(path, second, sources, last_report, history=[
        {"attempt": 1, "status": first_report.status,
         "issues": [i.model_dump() for i in first_report.issues]},
        {"attempt": 2, "status": last_report.status, "issues": []},
    ])
    for name in ("site-enabled", "site-disabled"):
        folder = examples / "targets" / name
        outcome = investigate(path, folder, context_path=folder / "context.json", allow_demo=True)
        print(f"[INVESTIGATE] {name}: {outcome.status}")
        for check in outcome.checks:
            print(f"        {check.condition_id}: {check.state} ({check.observed})")
    print(f"Skill artifact: {path}")
    print("CAUTION: DEMO_ONLY cannot be investigated without --allow-demo")
    return path
