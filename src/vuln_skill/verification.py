"""Fail-closed verification with literal quote provenance and omission checks.

'VERIFIED' is an automated evidence-policy result, not a guarantee of truth.
"""
from __future__ import annotations

from .models import (ApplicabilityModel, Issue, SourceRecord, VerificationJudgment,
                     VerificationReport, utc_now)
from .security import normalize, quote_is_present


def check_structure(model: ApplicabilityModel, sources: list[SourceRecord]) -> list[Issue]:
    issues: list[Issue] = []
    source_by_id = {s.id: s for s in sources}
    if not sources or not any(s.id == "CVE-CNA" for s in sources):
        issues.append(Issue(kind="NO_PRIMARY_RECORD", description="A published official CNA record is required"))
    if len({s.authority for s in sources}) < 2:
        issues.append(Issue(kind="SOURCE_DIVERSITY", description="At least two separately retrieved source families are required"))
    if not model.cve_id.startswith("CVE-") or not model.product.strip() or not model.summary.strip():
        issues.append(Issue(kind="INVALID_PRODUCT", description="Missing CVE ID, product, or summary"))
    elif not any(normalize(model.product) in normalize(src.text) for src in sources):
        issues.append(Issue(kind="UNVERIFIED_PRODUCT", description="Product name is not evidenced in retrieved source text"))
    ids = [c.id for c in model.conditions]
    if not ids or len(ids) > 30 or len(ids) != len(set(ids)):
        issues.append(Issue(kind="INVALID_CONDITIONS", description="Expected 1-30 conditions with unique IDs"))
    if not model.groups:
        issues.append(Issue(kind="NO_APPLICABILITY_LOGIC", description="Applicability condition groups are missing"))
    present: set[str] = set()
    for group in model.groups:
        if not group.any_of:
            issues.append(Issue(kind="EMPTY_GROUP", description="An OR group has no conditions"))
        for item in group.any_of:
            if item not in ids:
                issues.append(Issue(kind="UNKNOWN_CONDITION", description=f"Unknown condition ID {item}"))
            present.add(item)
    for cond in model.conditions:
        if cond.id not in present:
            issues.append(Issue(kind="UNUSED_CONDITION", condition_id=cond.id,
                                description="Condition is omitted from applicability expression"))
        source = source_by_id.get(cond.evidence_source_id)
        if source is None or not quote_is_present(cond.evidence_quote, source.text):
            issues.append(Issue(kind="INVALID_SOURCE_QUOTE", condition_id=cond.id,
                                description="Claim's exact supporting quote is absent from its cited source"))
        if cond.probe_kind == "wordpress_version":
            if not any(model.plugin_slug.lower() in src.text.lower() for src in sources):
                issues.append(Issue(kind="UNVERIFIED_SLUG", condition_id=cond.id,
                                    description="Plugin slug not present in retrieved public evidence; cannot safely assume a target path"))
            expected_path = f"wp-content/plugins/{model.plugin_slug}"
            if model.ecosystem.lower() != "wordpress" or not model.plugin_slug or cond.probe_path != expected_path:
                issues.append(Issue(kind="UNSAFE_PROBE", condition_id=cond.id,
                                    description="WordPress version probe requires a verified plugin slug and plugin directory"))
            if cond.category != "version":
                issues.append(Issue(kind="INVALID_PROBE", condition_id=cond.id,
                                    description="WordPress version probe must check a version condition"))
        if cond.probe_kind == "context_value" and not cond.probe_key:
            issues.append(Issue(kind="INVALID_PROBE", condition_id=cond.id,
                                description="context_value requires a context key"))
        if cond.probe_kind in ("file_contains", "file_exists") and not cond.probe_path:
            issues.append(Issue(kind="INVALID_PROBE", condition_id=cond.id,
                                description="file probe requires a target-relative path"))
    return issues


def check_judgment(model: ApplicabilityModel, sources: list[SourceRecord],
                   judgment: VerificationJudgment) -> list[Issue]:
    issues: list[Issue] = []
    source_by_id = {s.id: s for s in sources}
    cond_by_id = {c.id: c for c in model.conditions}
    seen = set()
    for decision in judgment.decisions:
        cid = decision.condition_id
        if cid in seen or cid not in cond_by_id:
            issues.append(Issue(kind="INVALID_DECISION", condition_id=cid,
                                description="Duplicate or unknown verifier decision"))
            continue
        seen.add(cid)
        if decision.verdict != "SUPPORTED":
            issues.append(Issue(kind="CLAIM_NOT_SUPPORTED", condition_id=cid,
                                description=f"{decision.verdict}: {decision.reason}"))
        source = source_by_id.get(decision.evidence_source_id)
        if source is None or not quote_is_present(decision.evidence_quote, source.text):
            issues.append(Issue(kind="INVALID_VERIFICATION_EVIDENCE", condition_id=cid,
                                description="Verification must cite a verbatim quote in fresh retrieved evidence"))
        elif source_by_id.get(cond_by_id[cid].evidence_source_id) and (
                source.authority == source_by_id[cond_by_id[cid].evidence_source_id].authority):
            issues.append(Issue(kind="NO_CROSS_SOURCE_SUPPORT", condition_id=cid,
                                description="Verification must cite another source family than extraction"))
    for cid in cond_by_id.keys() - seen:
        issues.append(Issue(kind="MISSING_DECISION", condition_id=cid,
                            description="Verifier did not evaluate this condition"))
    for missing in judgment.missing_conditions:
        source = source_by_id.get(missing.evidence_source_id)
        if source is None or not quote_is_present(missing.evidence_quote, source.text):
            issues.append(Issue(kind="UNSUPPORTED_MISSING_CLAIM", description=
                                f"Verifier proposed a missing prerequisite without evidence: {missing.description}"))
        else:
            issues.append(Issue(kind="MISSING_CONDITION", description=missing.description))
    return issues


def build_report(model: ApplicabilityModel, sources: list[SourceRecord],
                 judgment: VerificationJudgment, *, mode: str = "live", attempts: int = 1) -> VerificationReport:
    issues = check_structure(model, sources) + check_judgment(model, sources, judgment)
    if mode == "demo":
        status = "DEMO_ONLY" if not issues else "NEEDS_REVIEW"
        note = ("Demonstration fixture. Evidence and configuration are illustrative; "
                "this report is NOT an authoritative CVE verification.")
    else:
        status = "VERIFIED" if not issues else "NEEDS_REVIEW"
        note = ("Automated evidence-policy verification; NOT a guarantee of applicability, "
                "exploitability, or absence of exploitation. Review critical findings.")
    return VerificationReport(status=status, mode=mode, verified_at=utc_now(), attempts=attempts,
                              model_sha256="", skill_sha256="", source_urls=[s.url for s in sources],
                              decisions=judgment.decisions, issues=issues, note=note)
