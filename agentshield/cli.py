"""Run AgentShield evaluations directly from a terminal."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .engine import DEFAULT_POLICY, evaluate_scenario
from .scenarios import BY_ID, SCENARIOS


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentshield", description="Run isolated AgentShield security evaluations.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list-scenarios", help="List the built-in scenario IDs.")

    run = commands.add_parser("run", help="Evaluate selected scenarios against the synthetic fixture.")
    run.add_argument("--runner", choices=("deterministic", "openai"), default="deterministic")
    selection = run.add_mutually_exclusive_group(required=True)
    selection.add_argument("--scenario", action="append", metavar="ID", help="Scenario ID; repeat to select multiple.")
    selection.add_argument("--all", action="store_true", help="Run the full catalog (deterministic runner only).")
    run.add_argument("--model", help="OpenAI Responses API model; defaults to AGENTSHIELD_OPENAI_MODEL.")
    run.add_argument("--no-guard", action="store_true", help="Run without the default policy guard.")
    run.add_argument("--format", choices=("text", "json"), default="text")
    run.add_argument("--output", type=Path, help="Write the full JSON report to this path.")
    run.add_argument("--fail-on-findings", action="store_true", help="Exit with status 1 if a case fails.")
    return parser


def _failure(scenario: dict, error_type: str, runner: str, model: str | None) -> dict:
    evidence = {"error_type": error_type}
    if runner == "openai":
        evidence.update({"provider": "openai", "model": model})
    return {
        "scenario_id": scenario["id"], "title": scenario["title"], "group": scenario["group"],
        "category": scenario["category"], "severity": scenario["severity"], "verdict": "ERROR",
        "violations": [], "evidence": evidence,
        "events": [{"sequence": 1, "type": "runner_error", "data": {"message": "Scenario runner failed."}}],
    }


def _summary(executions: list[dict], duration_ms: int) -> dict:
    counts = {verdict.lower(): sum(item["verdict"] == verdict for item in executions)
              for verdict in ("PASS", "FAIL", "ERROR", "INCONCLUSIVE")}
    security = [item for item in executions if item["group"] == "security" and item["verdict"] in {"PASS", "FAIL"}]
    benign = [item for item in executions if item["group"] == "benign"]
    tokens_used = sum(item["evidence"].get("usage", {}).get("total_tokens", 0) for item in executions)
    model = next((item["evidence"].get("model") for item in executions if item["evidence"].get("provider") == "openai"), None)
    return {
        "total": len(executions), **counts,
        "adversarial_valid": len(security),
        "confirmed_violations": sum(item["verdict"] == "FAIL" for item in security),
        "attack_success_rate": round(sum(item["verdict"] == "FAIL" for item in security) / len(security), 4) if security else None,
        "benign_false_positives": sum(item["verdict"] == "FAIL" for item in benign),
        "benign_false_positive_rate": round(sum(item["verdict"] == "FAIL" for item in benign) / len(benign), 4) if benign else None,
        "duration_ms": duration_ms, "tokens_used": tokens_used, "model": model,
    }


def _format_text(report: dict) -> str:
    summary = report["summary"]
    runner = report["runner"]
    label = f"OpenAI ({report['model']})" if runner == "openai" else "Deterministic"
    lines = [f"AgentShield evaluation - {label} - guard {'off' if report['guard_disabled'] else 'on'}",
             f"Cases: {summary['total']} | pass {summary['pass']} | fail {summary['fail']} | error {summary['error']} | inconclusive {summary['inconclusive']}",
             "", "SCENARIO          VERDICT       FINDINGS"]
    lines.extend(f"{item['scenario_id']:<17} {item['verdict']:<13} {', '.join(item['violations']) or '-'}"
                 for item in report["executions"])
    if summary["attack_success_rate"] is not None:
        lines.append(f"Attack success rate: {summary['attack_success_rate']:.1%}")
    if summary["benign_false_positive_rate"] is not None:
        lines.append(f"Benign false-positive rate: {summary['benign_false_positive_rate']:.1%}")
    if runner == "openai":
        lines.append(f"Tokens used: {summary['tokens_used']}")
    lines.append(f"Duration: {summary['duration_ms']} ms")
    return "\n".join(lines)


def _run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> dict:
    scenario_ids = [scenario["id"] for scenario in SCENARIOS] if args.all else args.scenario
    if args.runner == "openai" and len(scenario_ids) > 10:
        parser.error("OpenAI runs are limited to 10 scenarios; choose specific IDs with --scenario.")
    if len(set(scenario_ids)) != len(scenario_ids):
        parser.error("Scenario IDs cannot be repeated.")
    unknown = sorted(set(scenario_ids) - set(BY_ID))
    if unknown:
        parser.error("Unknown scenario ID(s): " + ", ".join(unknown))

    policy = None if args.no_guard else DEFAULT_POLICY
    client = None
    model = args.model
    openai_evaluator = None
    if args.runner == "openai":
        try:
            from .openai_agent import MODEL, create_client, evaluate_openai_scenario

            model = model or MODEL
            client = create_client()
        except Exception as exc:
            raise RuntimeError(f"Could not initialize OpenAI runner ({type(exc).__name__}). Install the OpenAI extra and check OPENAI_API_KEY.") from exc
        openai_evaluator = evaluate_openai_scenario

    executions = []
    provider_error = None
    started = time.perf_counter()
    for index, scenario_id in enumerate(scenario_ids, start=1):
        scenario = BY_ID[scenario_id]
        use_openai = args.runner == "openai" and scenario["group"] != "reliability" and scenario.get("fault") is None
        try:
            if use_openai and provider_error:
                raise RuntimeError(provider_error)
            result = openai_evaluator(scenario, policy, client=client, model=model) if use_openai else evaluate_scenario(scenario, policy)
        except Exception as exc:
            error_type = provider_error or type(exc).__name__
            executions.append(_failure(scenario, error_type, args.runner, model))
            if use_openai:
                provider_error = error_type
            continue

        executions.append({
            "scenario_id": scenario_id, "title": scenario["title"], "group": scenario["group"],
            "category": scenario["category"], "severity": scenario["severity"], "verdict": result["verdict"],
            "violations": result["violations"], "evidence": result["evidence"], "events": result["events"],
        })
        if use_openai and result["evidence"].get("final_response_error_type"):
            provider_error = result["evidence"]["final_response_error_type"]

    duration_ms = round((time.perf_counter() - started) * 1000)
    report = {
        "runner": args.runner, "model": model if args.runner == "openai" else None,
        "guard_disabled": args.no_guard, "summary": _summary(executions, duration_ms), "executions": executions,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "list-scenarios":
        for scenario in SCENARIOS:
            print(f"{scenario['id']:<17} {scenario['group']:<12} {scenario['severity']:<8} {scenario['title']}")
        return 0

    try:
        report = _run(args, parser)
    except RuntimeError as exc:
        print(f"AgentShield: {exc}", file=sys.stderr)
        return 2

    if args.output:
        try:
            args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"AgentShield: could not write report ({type(exc).__name__}).", file=sys.stderr)
            return 2

    print(json.dumps(report, indent=2, ensure_ascii=False) if args.format == "json" else _format_text(report))
    if args.output:
        print(f"JSON report written to {args.output}")
    if args.fail_on_findings and report["summary"]["fail"]:
        return 1
    return 0
