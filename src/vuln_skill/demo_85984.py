"""Second offline demonstration: four-configuration AND for CVE-2026-85984.

Publicly described prerequisites; synthetic config keys, not WordPress database keys.
No live retrieval, no proof of a production deployment's state.
"""
from __future__ import annotations

from pathlib import Path

from .compiler import write_skill
from .investigation import investigate
from .models import (ApplicabilityModel, Condition, ConditionGroup, Decision,
                     MissingCondition, SourceRecord, VerificationJudgment, utc_now)
from .verification import build_report

CVE_ID = "CVE-2026-85984"
VERSION_QUOTE = "in all versions up to, and including, 5.5.5"
SETTINGS_QUOTE = ("WP Login OTP, Login with Only OTP, Allow Users to Login with Username "
                  "and Password, and Admin OTP Bypass")
TEXT = (
    "The miniOrange OTP Login, Verification and SMS Notifications plugin for WordPress "
    "is vulnerable to Authentication Bypass via the mo_wp_login_intent parameter in all "
    "versions up to, and including, 5.5.5. This is due to a missing password-intent "
    "guard in the plugin login handler. Exploitation is conditional on a site administrator "
    "having simultaneously enabled the following plugin options: WP Login OTP, "
    "Login with Only OTP, Allow Users to Login with Username and Password, and Admin OTP Bypass. "
    "Reference: https://plugins.trac.wordpress.org/browser/miniorange-otp-verification/"
)
SETTINGS = (
    ("wp_login_otp", "WP Login OTP"),
    ("login_only_otp", "Login with Only OTP"),
    ("username_password_allowed", "Allow Users to Login with Username and Password"),
    ("admin_otp_bypass", "Admin OTP Bypass"),
)


def demo_sources() -> list[SourceRecord]:
    return [
        SourceRecord(id="CVE-CNA", title="Cached CNA-style example (demo only)",
                     url="https://cveawg.mitre.org/api/cve/CVE-2026-85984",
                     authority="CVE/CNA", text=TEXT, fetched_at=utc_now()),
        SourceRecord(id="GHSA-1", title="Cached GHSA-style example (demo only)",
                     url="https://github.com/advisories/GHSA-38wg-7f73-vq67",
                     authority="GHSA", text=TEXT, fetched_at=utc_now()),
    ]


def demo_model(*, complete: bool) -> ApplicabilityModel:
    conditions = [Condition(
        id="affected_version", category="version", description="Plugin version <= 5.5.5",
        comparison="lte", expected="5.5.5", evidence_source_id="CVE-CNA",
        evidence_quote=VERSION_QUOTE, probe_kind="wordpress_version",
        probe_path="wp-content/plugins/miniorange-otp-verification", probe_key="")]
    groups = [ConditionGroup(any_of=["affected_version"])]
    if complete:
        for key, label in SETTINGS:
            conditions.append(Condition(
                id=key, category="configuration", description=f"{label} must be enabled",
                comparison="eq", expected="true", evidence_source_id="GHSA-1",
                evidence_quote=SETTINGS_QUOTE, probe_kind="context_value", probe_path="",
                probe_key=f"settings.{key}"))
            groups.append(ConditionGroup(any_of=[key]))
    return ApplicabilityModel(cve_id=CVE_ID,
                              product="miniOrange OTP Login, Verification and SMS Notifications",
                              ecosystem="wordpress", plugin_slug="miniorange-otp-verification",
                              summary="Authentication bypass depends on four simultaneous login settings.",
                              conditions=conditions, groups=groups)


def demo_judgment(*, complete: bool) -> VerificationJudgment:
    decisions = [Decision(condition_id="affected_version", verdict="SUPPORTED",
                          evidence_source_id="GHSA-1", evidence_quote=VERSION_QUOTE,
                          reason="Version upper bound is in the cached evidence")]
    missing = []
    for key, label in SETTINGS:
        if complete:
            decisions.append(Decision(condition_id=key, verdict="SUPPORTED",
                                      evidence_source_id="CVE-CNA", evidence_quote=SETTINGS_QUOTE,
                                      reason="Required setting appears in the explicit four-way list"))
        else:
            missing.append(MissingCondition(description=f"{label} must be enabled",
                                            evidence_source_id="GHSA-1", evidence_quote=SETTINGS_QUOTE))
    return VerificationJudgment(decisions=decisions, missing_conditions=missing)


def run_demo_85984(output: Path, *, examples: Path) -> Path:
    sources = demo_sources()
    print("DEMO ONLY: no live verification. Settings are synthetic operator-attested context keys.")
    print("[1/2] CREATE: version-only candidate for CVE-2026-85984")
    failed = build_report(demo_model(complete=False), sources,
                          demo_judgment(complete=False), mode="demo", attempts=1)
    print(f"[1/2] VERIFY: {failed.status}")
    for issue in failed.issues:
        print(f"        {issue.kind}: {issue.description}")
    print("[2/2] REPAIR: add all four required configuration conditions (AND)")
    model = demo_model(complete=True)
    report = build_report(model, sources, demo_judgment(complete=True), mode="demo", attempts=2)
    if report.status != "DEMO_ONLY":
        raise RuntimeError(f"Demo fixture verification failed: {report.issues}")
    print("[2/2] VERIFY: DEMO_ONLY (fixture checked; NOT authoritative verification)")
    path = output / f"{CVE_ID}.skill"
    write_skill(path, model, sources, report, history=[
        {"attempt": 1, "status": failed.status,
         "issues": [issue.model_dump() for issue in failed.issues]},
        {"attempt": 2, "status": report.status, "issues": []},
    ])
    for label in ("otp-all-enabled", "otp-bypass-disabled"):
        target = examples / "targets" / label
        outcome = investigate(path, target, context_path=target / "context.json", allow_demo=True)
        print(f"[INVESTIGATE] {label}: {outcome.status}")
        for check in outcome.checks:
            print(f"        {check.condition_id}: {check.state} ({check.observed})")
    print(f"Skill artifact: {path}")
    return path
