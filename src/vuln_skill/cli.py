"""Vuln-Skill command-line interface."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .demo import run_demo
from .investigation import InvestigationError, investigate
from .llm import OpenAIBackend
from .workflow import WorkflowError, check, create


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-skill",
        description="Create, independently check, and locally investigate CVE applicability."
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    create_p = sub.add_parser("create", help="Collect sources, generate, verify and repair a Skill")
    create_p.add_argument("cve", help="CVE ID, e.g. CVE-2026-82901")
    create_p.add_argument("--output-dir", type=Path, default=Path("generated"))
    create_p.add_argument("--max-attempts", type=int, default=3)
    create_p.add_argument("--model", help="OpenAI model used for extraction")
    create_p.add_argument("--verify-model", help="Optional different model used for verification")
    create_p.add_argument("--force", action="store_true", help="Replace an existing generated artifact")
    check_p = sub.add_parser("check", help="Re-verify an existing Skill using fresh public evidence")
    check_p.add_argument("skill", type=Path)
    check_p.add_argument("--verify-model")
    investigate_p = sub.add_parser("investigate", help="Run a verified, read-only local investigation")
    investigate_p.add_argument("skill", type=Path)
    investigate_p.add_argument("target", type=Path)
    investigate_p.add_argument("--context", type=Path, help="Explicit local JSON evidence; never sent to LLM")
    investigate_p.add_argument("--json", dest="json_output", type=Path, help="Save JSON investigation report")
    investigate_p.add_argument("--max-age-days", type=int, default=30)
    investigate_p.add_argument("--allow-demo", action="store_true", help="Explicitly allow DEMO_ONLY fixture skills")
    demo_p = sub.add_parser("demo", help="API-free demo; uses labeled offline fixtures (NOT live verification)")
    demo_p.add_argument("--output-dir", type=Path, default=Path("demo-output"))
    demo_p.add_argument("--cve", choices=["CVE-2026-82901", "CVE-2026-85984"],
                        default="CVE-2026-82901", help="Select an offline CVE demonstration")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    try:
        if args.command == "create":
            backend = OpenAIBackend(model=args.model, verify_model=args.verify_model)
            path, report = create(args.cve, args.output_dir, max_attempts=args.max_attempts,
                                  force=args.force, backend=backend)
            print(f"Output: {path}\nStatus: {report.status}")
            if report.status != "VERIFIED":
                print("Needs review: evidence insufficient. No target investigation permitted.")
                return 2
            return 0
        if args.command == "check":
            backend = OpenAIBackend(verify_model=args.verify_model)
            report = check(args.skill, backend=backend)
            print(f"Status: {report.status}; issues: {len(report.issues)}")
            for issue in report.issues:
                print(f"  {issue.kind} {issue.condition_id}: {issue.description}")
            return 0 if report.status == "VERIFIED" else 2
        if args.command == "investigate":
            report = investigate(args.skill, args.target, context_path=args.context,
                                 allow_demo=args.allow_demo, max_age_days=args.max_age_days)
            print(f"{report.cve_id}: {report.status}")
            for probe in report.checks:
                print(f"  {probe.condition_id:24} {probe.state:8} {probe.observed}")
            print(report.note)
            if args.json_output:
                args.json_output.parent.mkdir(parents=True, exist_ok=True)
                args.json_output.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
                print(f"Report saved: {args.json_output}")
            return 0 if report.status not in ("INCONCLUSIVE",) else 2
        if args.command == "demo":
            example_dir = Path(__file__).resolve().parents[2] / "examples"
            if not example_dir.exists():
                raise RuntimeError("Demo fixtures not installed. Use the GitHub source checkout for the demo.")
            if args.cve == "CVE-2026-85984":
                from .demo_85984 import run_demo_85984
                run_demo_85984(args.output_dir, examples=example_dir)
            else:
                run_demo(args.output_dir, examples=example_dir)
            return 0
        return 1
    except (RuntimeError, ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
