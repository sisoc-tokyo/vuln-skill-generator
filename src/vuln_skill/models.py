"""Strict models shared by extraction, verification and investigation.

The model contains only declarative probes. No generated code is executed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceRecord(StrictModel):
    id: str
    title: str
    url: str
    authority: str
    text: str
    fetched_at: str


class Condition(StrictModel):
    id: str
    category: Literal["version", "configuration", "module", "authentication", "exposure", "runtime", "other"]
    description: str
    comparison: Literal["eq", "ne", "lt", "lte", "gt", "gte", "contains", "present", "absent"]
    expected: str
    evidence_source_id: str
    evidence_quote: str
    # These are declarative, read-only probes. "manual" explicitly means no reliable automated probe is known.
    probe_kind: Literal["wordpress_version", "context_value", "file_exists", "file_contains", "manual"]
    probe_path: str  # relative to target root; empty when not applicable
    probe_key: str  # dot-path into explicitly supplied context JSON; empty when not applicable


class ConditionGroup(StrictModel):
    """AND of groups; each group is an OR of condition IDs (CNF)."""
    any_of: list[str]


class ApplicabilityModel(StrictModel):
    cve_id: str
    product: str
    ecosystem: str
    plugin_slug: str  # empty if unknown / not WordPress
    summary: str
    conditions: list[Condition]
    groups: list[ConditionGroup]


class Decision(StrictModel):
    condition_id: str
    verdict: Literal["SUPPORTED", "CONTRADICTED", "INSUFFICIENT_EVIDENCE"]
    evidence_source_id: str
    evidence_quote: str
    reason: str


class MissingCondition(StrictModel):
    description: str
    evidence_source_id: str
    evidence_quote: str


class VerificationJudgment(StrictModel):
    decisions: list[Decision]
    missing_conditions: list[MissingCondition]


class Issue(StrictModel):
    kind: str
    description: str
    condition_id: str = ""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class VerificationReport(StrictModel):
    status: Literal["VERIFIED", "NEEDS_REVIEW", "DEMO_ONLY"]
    mode: Literal["live", "demo"]
    verified_at: str
    attempts: int
    model_sha256: str
    skill_sha256: str
    source_urls: list[str]
    decisions: list[Decision]
    issues: list[Issue]
    note: str


class ProbeResult(StrictModel):
    condition_id: str
    description: str
    state: Literal["TRUE", "FALSE", "UNKNOWN", "ERROR"]
    observed: str
    method: str


class InvestigationReport(StrictModel):
    cve_id: str
    target: str
    status: Literal["NOT_APPLICABLE", "APPLICABLE", "EXPOSED", "INCONCLUSIVE"]
    checked_at: str
    checks: list[ProbeResult]
    note: str
