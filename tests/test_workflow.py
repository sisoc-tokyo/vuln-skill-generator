from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_skill.compiler import read_skill, validate_integrity, write_skill
from vuln_skill.demo import _judgment, _model, _sources, run_demo
from vuln_skill.investigation import InvestigationError, investigate
from vuln_skill.models import VerificationJudgment
from vuln_skill.security import quote_is_present, safe_relative_path, url_allowed
from vuln_skill.verification import build_report
from vuln_skill.workflow import check, create


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_demo_rejects_missing_prerequisite_then_repairs(tmp_path: Path):
    path = run_demo(tmp_path, examples=EXAMPLES)
    model, verification = read_skill(path)
    assert verification.status == "DEMO_ONLY"
    assert len(model.conditions) == 2
    assert validate_integrity(path, verification)
    history = json.loads((path / "attempts.json").read_text())
    assert history[0]["status"] == "NEEDS_REVIEW"
    assert any(i["kind"] == "MISSING_CONDITION" for i in history[0]["issues"])
    assert history[1]["status"] == "DEMO_ONLY"


def test_same_version_two_different_configurations(tmp_path: Path):
    path = run_demo(tmp_path, examples=EXAMPLES)
    first = EXAMPLES / "targets/site-enabled"
    second = EXAMPLES / "targets/site-disabled"
    yes = investigate(path, first, context_path=first / "context.json", allow_demo=True)
    no = investigate(path, second, context_path=second / "context.json", allow_demo=True)
    assert yes.status == "APPLICABLE"
    assert no.status == "NOT_APPLICABLE"
    assert yes.checks[0].observed == no.checks[0].observed == "3.5.49"
    assert yes.checks[1].state == "TRUE"
    assert no.checks[1].state == "FALSE"


def test_unknown_context_is_inconclusive(tmp_path: Path):
    path = run_demo(tmp_path, examples=EXAMPLES)
    target = EXAMPLES / "targets/site-enabled"
    result = investigate(path, target, allow_demo=True)
    assert result.status == "INCONCLUSIVE"
    assert any(x.state == "UNKNOWN" for x in result.checks)


def test_demo_only_requires_explicit_opt_in(tmp_path: Path):
    path = run_demo(tmp_path, examples=EXAMPLES)
    with pytest.raises(InvestigationError, match="not VERIFIED"):
        investigate(path, EXAMPLES / "targets/site-enabled")


def test_changed_skill_fails_integrity_check(tmp_path: Path):
    path = run_demo(tmp_path, examples=EXAMPLES)
    model_path = path / "applicability.json"
    model_path.write_text(model_path.read_text() + "\n", encoding="utf-8")
    with pytest.raises(InvestigationError, match="changed"):
        investigate(path, EXAMPLES / "targets/site-enabled", allow_demo=True)


def test_source_quote_evidence_is_literal():
    assert quote_is_present("PDF Generator module is enabled", _sources()[0].text)
    assert not quote_is_present("fabricated condition with no supporting quote", _sources()[0].text)


def test_missing_claim_and_wrong_quote_are_rejected():
    model = _model(False)
    report = build_report(model, _sources(), _judgment(False))
    assert report.status == "NEEDS_REVIEW"
    assert any(x.kind == "MISSING_CONDITION" for x in report.issues)
    model2 = _model(True)
    model2.conditions[0].evidence_quote = "This completely invented quote is not present"
    report2 = build_report(model2, _sources(), _judgment(True))
    assert report2.status == "NEEDS_REVIEW"
    assert any(x.kind == "INVALID_SOURCE_QUOTE" for x in report2.issues)


def test_source_diversity_failure_is_fail_closed():
    model = _model(True)
    report = build_report(model, _sources()[:1], _judgment(True))
    assert report.status == "NEEDS_REVIEW"
    assert any(x.kind == "SOURCE_DIVERSITY" for x in report.issues)


def test_live_verification_passes_mocked_two_family_evidence():
    report = build_report(_model(True), _sources(), _judgment(True))
    assert report.status == "VERIFIED"
    assert not report.issues


class FakeBackend:
    def __init__(self):
        self.attempts = 0
        self.review_calls = 0

    def extract(self, cve_id, sources, *, prior=None, feedback=None):
        self.attempts += 1
        assert cve_id == "CVE-2026-82901"
        if self.attempts > 1:
            assert prior is not None
            assert any(item["kind"] == "MISSING_CONDITION" for item in feedback)
        return _model(include_module=self.attempts > 1)

    def review(self, model, sources):
        self.review_calls += 1
        return _judgment(include_module=len(model.conditions) > 1)


def test_real_create_repair_check_injected_provider(tmp_path: Path):
    fake = FakeBackend()
    folder, report = create("CVE-2026-82901", tmp_path, max_attempts=3, backend=fake, collector=lambda _: _sources())
    assert fake.attempts == 2
    assert report.status == "VERIFIED"
    model, saved = read_skill(folder)
    assert saved.status == "VERIFIED"
    assert validate_integrity(folder, saved)
    outcome = investigate(folder, EXAMPLES / "targets/site-enabled",
                          context_path=EXAMPLES / "targets/site-enabled/context.json")
    assert outcome.status == "APPLICABLE"
    checked = check(folder, backend=fake, collector=lambda _: _sources())
    assert checked.status == "VERIFIED"
    assert fake.review_calls == 3


def test_untrusted_url_and_traversal_rejected(tmp_path: Path):
    assert url_allowed("https://api.github.com/advisories?cve_id=CVE-2026-82901")
    assert not url_allowed("http://api.github.com/advisories")
    assert not url_allowed("https://127.0.0.1/private")
    assert not url_allowed("https://github.com.evil.example/")
    with pytest.raises(ValueError, match="Unsafe"):
        safe_relative_path(tmp_path, "../outside")
    with pytest.raises(ValueError, match="Unsafe"):
        safe_relative_path(tmp_path, "/etc/passwd")
    (tmp_path / "link").symlink_to("/etc/passwd")
    with pytest.raises(ValueError, match="Symlink"):
        safe_relative_path(tmp_path, "link")


def test_four_settings_demo_and_pair(tmp_path: Path):
    from vuln_skill.demo_85984 import run_demo_85984
    path = run_demo_85984(tmp_path, examples=EXAMPLES)
    model, report = read_skill(path)
    assert len(model.conditions) == 5
    assert len(model.groups) == 5
    assert report.status == "DEMO_ONLY"
    enabled = EXAMPLES / "targets/otp-all-enabled"
    disabled = EXAMPLES / "targets/otp-bypass-disabled"
    on = investigate(path, enabled, context_path=enabled / "context.json", allow_demo=True)
    off = investigate(path, disabled, context_path=disabled / "context.json", allow_demo=True)
    assert on.status == "APPLICABLE"
    assert off.status == "NOT_APPLICABLE"
    assert on.checks[0].observed == off.checks[0].observed == "5.5.5"
    assert [c.state for c in off.checks].count("FALSE") == 1


def test_unsafe_slug_does_not_verify():
    m = _model(True)
    m.plugin_slug = "not-the-real-plugin"
    m.conditions[0].probe_path = "wp-content/plugins/not-the-real-plugin"
    rep = build_report(m, _sources(), _judgment(True))
    assert rep.status == "NEEDS_REVIEW"
    assert any(x.kind == "UNVERIFIED_SLUG" for x in rep.issues)


def test_missing_plugin_path_is_unknown_not_safety_proof(tmp_path: Path):
    path = run_demo(tmp_path / "output", examples=EXAMPLES)
    target = tmp_path / "empty-target"
    target.mkdir()
    outcome = investigate(path, target, allow_demo=True)
    assert outcome.status == "INCONCLUSIVE"
    assert outcome.checks[0].state == "UNKNOWN"


def test_unverified_product_cannot_be_approved():
    model = _model(True)
    model.product = "Completely Fabricated Product"
    report = build_report(model, _sources(), _judgment(True))
    assert report.status == "NEEDS_REVIEW"
    assert any(x.kind == "UNVERIFIED_PRODUCT" for x in report.issues)


def test_cve_identifier_prevents_output_path_injection(tmp_path: Path):
    from vuln_skill.workflow import WorkflowError
    with pytest.raises(WorkflowError, match="Expected CVE"):
        create("CVE-2026-1234/../../secrets", tmp_path, backend=FakeBackend(),
               collector=lambda _: _sources())


def test_openai_adapter_uses_structured_outputs_without_network():
    from vuln_skill.llm import OpenAIBackend
    from vuln_skill.models import ApplicabilityModel, VerificationJudgment

    class FakeResponses:
        def __init__(self):
            self.calls = []
        def parse(self, **kwargs):
            self.calls.append(kwargs)
            result = _model(True) if kwargs["text_format"] is ApplicabilityModel else _judgment(True)
            return type("Result", (), {"output_parsed": result})()
    calls = FakeResponses()
    backend = object.__new__(OpenAIBackend)
    backend.client = type("Client", (), {"responses": calls})()
    backend.model = "test-extractor"
    backend.verify_model = "test-verifier"
    model = backend.extract("CVE-2026-82901", _sources())
    judgment = backend.review(model, _sources())
    assert len(model.conditions) == 2
    assert len(judgment.decisions) == 2
    assert calls.calls[0]["text_format"] is ApplicabilityModel
    assert calls.calls[1]["text_format"] is VerificationJudgment
    assert calls.calls[0]["store"] is False
    assert calls.calls[0]["model"] == "test-extractor"
    assert calls.calls[1]["model"] == "test-verifier"
    assert "my-private-context.json" not in str(calls.calls)
