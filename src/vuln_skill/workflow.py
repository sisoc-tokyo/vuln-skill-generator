"""Orchestrate real collection/generation/verification/repair and offline examples."""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Callable

from .compiler import read_skill, validate_integrity, write_skill
from .llm import OpenAIBackend
from .models import ApplicabilityModel, SourceRecord, VerificationJudgment, VerificationReport
from .sources import collect_sources
from .verification import build_report


class WorkflowError(RuntimeError):
    pass


def _feedback(report: VerificationReport) -> list[dict]:
    return [x.model_dump() for x in report.issues]


def create(cve_id: str, output_dir: Path, *, max_attempts: int = 3, force: bool = False,
           backend: OpenAIBackend | None = None,
           collector: Callable[[str], list[SourceRecord]] = collect_sources) -> tuple[Path, VerificationReport]:
    if max_attempts not in range(1, 6):
        raise WorkflowError("max_attempts must be from 1 to 5")
    cve_id = cve_id.upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        raise WorkflowError("Expected CVE-YYYY-NNNN (or longer numeric ID)")
    dest = output_dir / f"{cve_id}.skill"
    if dest.exists() and not force:
        raise WorkflowError(f"Output already exists: {dest}. Use --force only if you intend to replace it.")
    backend = backend or OpenAIBackend()
    prior = None
    feedback: list[dict] = []
    history = []
    result_model = None
    result_sources = []
    result_report = None
    for attempt in range(1, max_attempts + 1):
        print(f"[{attempt}/{max_attempts}] CREATE: collecting {cve_id} public evidence")
        generation_sources = collector(cve_id)
        candidate = backend.extract(cve_id, generation_sources, prior=prior, feedback=feedback)
        if candidate.cve_id != cve_id:
            raise WorkflowError("Generator returned a model for the wrong CVE")
        print(f"[{attempt}/{max_attempts}] VERIFY: fresh collection and claim-level review")
        verification_sources = collector(cve_id)
        judgment = backend.review(candidate, verification_sources)
        # Recheck all candidate claims against newly fetched evidence, not just previous snapshot.
        report = build_report(candidate, verification_sources, judgment, attempts=attempt)
        history.append({"attempt": attempt, "status": report.status,
                        "issues": _feedback(report)})
        result_model, result_sources, result_report = candidate, verification_sources, report
        print(f"[{attempt}/{max_attempts}] {report.status}; issues={len(report.issues)}")
        if report.status == "VERIFIED":
            break
        # Source scarcity is not fixed by stochastic regeneration.
        non_retryable = {"SOURCE_DIVERSITY", "NO_PRIMARY_RECORD"}
        if any(issue.kind in non_retryable for issue in report.issues):
            print("Insufficient independent evidence; stopping retries safely")
            break
        feedback = _feedback(report)
        prior = candidate
    assert result_model is not None and result_report is not None
    if dest.exists():
        shutil.rmtree(dest)
    write_skill(dest, result_model, result_sources, result_report, history=history)
    return dest, result_report


def check(path: Path, *, backend: OpenAIBackend | None = None,
          collector: Callable[[str], list[SourceRecord]] = collect_sources) -> VerificationReport:
    model, existing = read_skill(path)
    backend = backend or OpenAIBackend()
    if not validate_integrity(path, existing):
        print("Content hash changed. Reverification required before investigation.")
    sources = collector(model.cve_id)
    judgment = backend.review(model, sources)
    report = build_report(model, sources, judgment, attempts=1)
    # Recompile a deterministic SKILL.md from the validated candidate.
    write_skill(path, model, sources, report)
    return report
