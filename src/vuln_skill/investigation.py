"""Read-only local investigation: never invokes a shell or LLM API."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from .compiler import read_skill, validate_integrity
from .models import ApplicabilityModel, Condition, InvestigationReport, ProbeResult, utc_now
from .security import safe_relative_path


class InvestigationError(RuntimeError):
    pass


def get_dotted(context: dict, path: str) -> Any:
    current: Any = context
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(path)
        current = current[part]
    return current


def _compare(observed: Any, comparison: str, expected: str) -> bool:
    if comparison in {"lt", "lte", "gt", "gte"}:
        left, right = Version(str(observed)), Version(str(expected))
        return {"lt": left < right, "lte": left <= right,
                "gt": left > right, "gte": left >= right}[comparison]
    def canon(value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value).strip().lower()
    left, right = canon(observed), canon(expected)
    if comparison == "eq":
        return left == right
    if comparison == "ne":
        return left != right
    if comparison == "contains":
        return right in left
    if comparison == "present":
        return bool(observed)
    if comparison == "absent":
        return not bool(observed)
    raise ValueError("Unsupported comparison")


def _wordpress_version(plugin_dir: Path) -> str | None:
    if not plugin_dir.is_dir():
        return None
    for file in sorted(plugin_dir.glob("*.php"))[:30]:
        if file.is_symlink() or file.stat().st_size > 2_000_000:
            continue
        header = file.open("rb").read(8192).decode("utf-8", errors="replace")
        if not re.search(r"(?im)^\s*(?:\*\s*)?Plugin Name:\s*\S", header):
            continue
        match = re.search(r"(?im)^\s*(?:\*\s*)?Version:\s*([^\r\n*]+)", header)
        if match:
            return match.group(1).strip()
    return None


def probe(condition: Condition, root: Path, context: dict) -> ProbeResult:
    observed = "not available"
    method = condition.probe_kind
    try:
        if condition.probe_kind == "manual":
            return ProbeResult(condition_id=condition.id, description=condition.description,
                               state="UNKNOWN", observed="Manual evidence required; no safe automated probe",
                               method="manual")
        if condition.probe_kind == "context_value":
            try:
                observed_value = get_dotted(context, condition.probe_key)
            except KeyError:
                return ProbeResult(condition_id=condition.id, description=condition.description,
                                   state="UNKNOWN", observed=f"No operator-supplied context key: {condition.probe_key}",
                                   method=method)
        elif condition.probe_kind == "wordpress_version":
            location = safe_relative_path(root, condition.probe_path)
            observed_value = _wordpress_version(location)
            if observed_value is None:
                # Missing expected directory does not prove absence (custom plugin paths exist).
                if not location.exists():
                    return ProbeResult(condition_id=condition.id, description=condition.description,
                                       state="UNKNOWN", observed="Expected plugin directory not found; cannot rule out alternate locations",
                                       method=method)
                return ProbeResult(condition_id=condition.id, description=condition.description,
                                   state="UNKNOWN", observed="No readable WordPress plugin version header",
                                   method=method)
        elif condition.probe_kind == "file_exists":
            observed_value = safe_relative_path(root, condition.probe_path).is_file()
        elif condition.probe_kind == "file_contains":
            file = safe_relative_path(root, condition.probe_path)
            if not file.is_file() or file.stat().st_size > 1_000_000:
                return ProbeResult(condition_id=condition.id, description=condition.description,
                                   state="UNKNOWN", observed="Target file missing or exceeds read limit",
                                   method=method)
            observed_value = file.read_text(encoding="utf-8", errors="replace")
        else:
            raise ValueError("Unknown probe kind")
        ok = _compare(observed_value, condition.comparison, condition.expected)
        observed = str(observed_value)
        if len(observed) > 160:
            observed = "[file contents omitted; local predicate evaluated]"
        return ProbeResult(condition_id=condition.id, description=condition.description,
                           state="TRUE" if ok else "FALSE", observed=observed, method=method)
    except (ValueError, OSError, InvalidVersion, TypeError, UnicodeError) as exc:
        return ProbeResult(condition_id=condition.id, description=condition.description,
                           state="ERROR", observed=f"Probe could not establish condition: {type(exc).__name__}",
                           method=method)


def evaluate(model: ApplicabilityModel, checks: list[ProbeResult]) -> str:
    states = {c.condition_id: c.state for c in checks}
    group_states = []
    for group in model.groups:
        values = [states.get(cid, "UNKNOWN") for cid in group.any_of]
        if "TRUE" in values:
            group_states.append("TRUE")
        elif all(v == "FALSE" for v in values):
            group_states.append("FALSE")
        else:
            group_states.append("UNKNOWN")
    if "FALSE" in group_states:
        return "NOT_APPLICABLE"
    if any(s != "TRUE" for s in group_states):
        return "INCONCLUSIVE"
    cond_by_id = {c.id: c for c in model.conditions}
    exposed = any(cond_by_id[cid].category == "exposure" and states.get(cid) == "TRUE"
                  for group in model.groups for cid in group.any_of)
    return "EXPOSED" if exposed else "APPLICABLE"


def investigate(skill_path: Path, target: Path, *, context_path: Path | None = None,
                allow_demo: bool = False, max_age_days: int = 30) -> InvestigationReport:
    model, report = read_skill(skill_path)
    if not validate_integrity(skill_path, report):
        raise InvestigationError("Skill contents changed since verification; run `vuln-skill check` again")
    if report.status != "VERIFIED":
        if not (allow_demo and report.status == "DEMO_ONLY" and report.mode == "demo"):
            raise InvestigationError("Skill is not VERIFIED; refusing local investigation")
    if max_age_days < 0:
        raise InvestigationError("max_age_days must not be negative")
    verified_at = datetime.fromisoformat(report.verified_at)
    if datetime.now(timezone.utc) - verified_at > __import__("datetime").timedelta(days=max_age_days):
        raise InvestigationError("Skill verification is stale; run `vuln-skill check` again")
    if not target.exists() or not target.is_dir():
        raise InvestigationError(f"Target must be an existing directory: {target}")
    context: dict = {}
    if context_path is not None:
        if context_path.stat().st_size > 200_000:
            raise InvestigationError("Context file too large")
        context = json.loads(context_path.read_text(encoding="utf-8"))
        if not isinstance(context, dict):
            raise InvestigationError("Context must be a JSON object")
    checks = [probe(cond, target, context) for cond in model.conditions]
    status = evaluate(model, checks)
    note = "Read-only local checks. UNKNOWN does not mean safe. No exploitation test was performed."
    if report.mode == "demo":
        note += " DEMO ONLY: synthetic context is not proof of real-world vulnerability."
    return InvestigationReport(cve_id=model.cve_id, target=str(target.resolve()),
                               status=status, checked_at=utc_now(), checks=checks, note=note)
