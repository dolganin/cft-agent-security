from __future__ import annotations

import argparse
import json
import logging
import os
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from agent.graph import build_graph
from agent.lab import ManagedAgentLab
from agent.llm import LLMUnavailableError
from agent.llm_model import FallbackLLMAgentModel
from agent.repository_scout import RepositoryScout
from app.config import settings
from app.e2e_inputs import build_real_initial_state
from architecture.service import ArchitectureService
from discovery.express_routes import build_express_source_map, link_candidates_to_routes
from discovery.scout import merge_scout_candidates, validate_scout_candidates
from discovery.service import ProjectDiscovery
from evaluation.artifact_history import persist_agent_trace
from pipeline.cancellation import RunCancelled, check_cancelled
from pipeline.errors import error_from_exception
from pipeline.gate import evaluate_gate
from pipeline.policy import classify_finding_gate
from pipeline.progress import PipelineProgressRecorder
from pr_analysis.git_diff import read_git_diff
from pr_analysis.service import PRAnalysisService
from reporting.builder import build_final_report
from reporting.presentation import render_final_report
from sast.profiles import (
    classify_diagnostics,
    load_scan_profile,
    validate_target_snapshot,
)
from sast.repository import JsonFindingRepository
from sast.semgrep_runner import SemgrepError, run_semgrep_scan
from schemas.errors import ErrorDetail
from schemas.pipeline import GateResult
from schemas.report import CIGateImpact, FinalReport, ReportFinding, VerificationSummary
from schemas.runtime import RuntimeServiceMap
from schemas.target import TargetProfile
from tools.runtime import LocalCodeReader

logger = logging.getLogger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run SAST, verify every normalized finding with the bounded agent workflow, "
            "write FinalReport JSON artifacts, and return a deterministic CI/CD gate."
        )
    )
    parser.add_argument(
        "--profile",
        default=str(settings.target_file),
        help="TargetProfile YAML",
    )
    parser.add_argument(
        "--target",
        help="Optional repository root override from TargetProfile",
    )
    parser.add_argument(
        "--architecture",
        help="Optional architecture YAML override from TargetProfile",
    )
    parser.add_argument(
        "--architecture-overrides",
        help="Optional YAML overrides for automatically derived architecture context",
    )
    parser.add_argument("--sast-config", default="auto", help="Semgrep config or digest-locked profile")
    parser.add_argument(
        "--output-dir",
        default="artifacts/security-pipeline",
        help="Root directory for SAST, reports, and gate artifacts",
    )
    parser.add_argument(
        "--findings",
        help="Use an existing normalized findings JSON instead of running SAST",
    )
    parser.add_argument(
        "--agent-mode",
        choices=("stub", "llm"),
        help="Override CFT_AGENT_MODE for this run",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=1,
        help="Controlled workflow iteration limit per finding",
    )
    parser.add_argument(
        "--full-reports",
        action="store_true",
        help="Print the full human-readable FinalReport for every finding",
    )
    parser.add_argument(
        "--base-ref",
        help="Base Git ref for optional PR-aware diff analysis",
    )
    parser.add_argument(
        "--head-ref",
        default="HEAD",
        help="Head Git ref for PR-aware diff analysis (default: HEAD)",
    )
    parser.add_argument(
        "--base-findings",
        help="Normalized findings JSON produced for --base-ref",
    )
    parser.add_argument(
        "--base-architecture",
        help="Optional base-revision architecture YAML for context comparison",
    )
    parser.add_argument("--scoring-reviews", help="Operator-reviewed, source-bound B08 JSON list")
    return parser.parse_args()


def run_pipeline(
    args: argparse.Namespace,
    *,
    profile_override: TargetProfile | None = None,
    runtime_services: RuntimeServiceMap | None = None,
    verification_profiles: tuple[TargetProfile, ...] = (),
) -> int:
    """Запускаем часть пайплайна SAST -> agent -> FinalReport -> Gate

    CI orchestrator передает discovered profile и service map уже поднятого sandbox
    Обычный CLI по-прежнему может вызвать функцию без них
    """
    if args.max_iterations < 1:
        raise SystemExit("--max-iterations must be at least 1")

    check_cancelled(getattr(args, "cancellation_token", None))
    profile_path = Path(args.profile).expanduser()
    profile = profile_override or TargetProfile.from_yaml(
        profile_path,
        repository_path_override=args.target,
        base_url_override=settings.target_base_url,
    )
    if profile.repository_path is None:
        raise SystemExit("TargetProfile.repository_path or --target is required")
    architecture_value = args.architecture or profile.architecture.file
    if architecture_value is None:
        raise SystemExit("TargetProfile.architecture.file or --architecture is required")

    target = profile.repository_path
    from scoring.review import load_reviews
    scoring_path = getattr(args, "scoring_reviews", None)
    scoring_reviews = load_reviews(scoring_path) if scoring_path else {}
    architecture = Path(architecture_value).expanduser().resolve()
    architecture_overrides = (
        Path(args.architecture_overrides).expanduser().resolve()
        if args.architecture_overrides
        else None
    )
    output_dir = Path(args.output_dir).expanduser()
    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    if scoring_path:
        # Freeze the parsed operator input rather than a mutable external path.
        (output_dir / "scoring-reviews.json").write_text(
            json.dumps([item.model_dump(mode="json") for item in scoring_reviews.values()],
                       indent=2) + "\n", encoding="utf-8",
        )
    progress = PipelineProgressRecorder(output_dir)

    if args.agent_mode:
        settings.agent_mode = args.agent_mode
    settings.target_file = profile_path
    settings.target_repository_path = target

    print("=" * 72)
    print("CFT SECURITY PIPELINE")
    print("=" * 72)
    print(f"Target profile: {profile.id}")
    print(f"Target: {target}")
    print(f"Agent mode: {settings.agent_mode}")

    pipeline_errors: list[ErrorDetail] = []
    # Без списка финдингов дальше проверять нечего, сразу возвращаем фейл гейт
    try:
        check_cancelled()
        findings_path = _resolve_findings(
            existing_findings=args.findings,
            target=target,
            sast_config=args.sast_config,
            output_dir=output_dir / "sast",
            service_resolver=profile.resolve_service,
        )
        check_cancelled()
    except RunCancelled:
        raise
    except (SemgrepError, OSError, ValueError, TypeError) as exc:
        pipeline_errors.append(
            error_from_exception(
                exc,
                layer="sast",
                public_message="SAST stage failed",
            )
        )
        gate = evaluate_gate([], errors=pipeline_errors)
        _write_gate(output_dir, gate)
        _print_gate(gate)
        return gate.exit_code

    findings = JsonFindingRepository(findings_path).list_findings()
    progress.sast_done(len(findings))
    discovery = getattr(args, "discovery", None)
    if settings.agent_mode == "llm" and discovery is None:
        check_cancelled()
        discovery = ProjectDiscovery().discover(target)
    findings = _append_scout_findings(
        findings, discovery, output_dir=output_dir,
        service_resolver=profile.resolve_service,
        progress=progress,
    )
    from agent.verification import register_source_artifacts

    profile = register_source_artifacts(profile, findings, target)
    if verification_profiles:
        if len({item.id for item in verification_profiles}) != len(verification_profiles):
            raise ValueError("Duplicate operator verification profiles")
        if any(item.repository_path != target or item.environment != profile.environment
               for item in verification_profiles):
            raise ValueError("Operator profiles must bind the same repository and environment")
        verification_profiles = tuple(register_source_artifacts(item, findings, target)
                                      for item in verification_profiles)
    if args.base_ref:
        if not args.base_findings:
            pipeline_errors.append(
                ErrorDetail(
                    code="VALIDATION_ERROR",
                    layer="pipeline",
                    message=(
                        "PR analysis requires --base-findings to distinguish new and "
                        "existing findings."
                    ),
                )
            )
        else:
            try:
                base_findings = JsonFindingRepository(args.base_findings).list_findings()
                diff = read_git_diff(target, base_ref=args.base_ref, head_ref=args.head_ref)
                base_architecture = (
                    ArchitectureService(args.base_architecture)
                    if args.base_architecture
                    else None
                )
                analyser = PRAnalysisService(
                    base_ref=args.base_ref,
                    head_ref=args.head_ref,
                    diff=diff,
                    base_architecture=base_architecture,
                    head_architecture=ArchitectureService(
                        architecture,
                        overrides_path=architecture_overrides,
                    ),
                )
                findings, pr_summary = analyser.analyse(
                    base_findings=base_findings,
                    head_findings=findings,
                )
                (output_dir / "pr-analysis.json").write_text(
                    pr_summary.model_dump_json(indent=2) + "\n",
                    encoding="utf-8",
                )
            except (OSError, RuntimeError, ValueError, TypeError) as exc:
                pipeline_errors.append(
                    error_from_exception(
                        exc,
                        layer="pipeline",
                        public_message="PR analysis failed",
                    )
                )
    print(f"Findings to verify: {len(findings)}")

    reports: list[FinalReport] = []
    report_paths: dict[str, str] = {}
    graph = build_graph()
    routing_records = []
    if findings:
        progress.verification_started()

    for index, finding in enumerate(findings):
        state = None
        result = None
        check_cancelled()
        print()
        location = f"{finding.file}:{finding.line_start or '?'}"
        print(f"[{index + 1}/{len(findings)}] {finding.rule_id} | {location}")
        progress.finding_started(
            index=index + 1,
            total=len(findings),
            finding_id=finding.id,
            title=finding.title,
            severity=finding.severity,
            rule_id=finding.rule_id,
            file=finding.file,
        )
        try:
            finding_profile = profile
            if verification_profiles:
                from agent.verification_routing import select_profile
                finding_profile, routing_reason = select_profile(finding, verification_profiles)
                routing_records.append({"finding_id": finding.id,
                                        "profile": finding_profile.id if finding_profile else None,
                                        "reason": routing_reason})
                if finding_profile is None:
                    report = _build_static_finding_report(finding, target,
                        scoring_review=scoring_reviews.get(finding.id), reason=routing_reason)
                    report.stop_reason = "binding_unavailable"
                    report_path = reports_dir / f"{index:03d}-{_safe_name(finding.id)}.json"
                    report_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
                    reports.append(report)
                    report_paths[finding.id] = str(report_path)
                    persist_agent_trace(output_dir, finding.id, {"finding": finding,
                        "status": report.status, "stop_reason": report.stop_reason})
                    progress.finding_finished(finding_id=finding.id, status=report.status)
                    print("  status=inconclusive capability=none context=unmapped")
                    continue
            service = finding_profile.resolve_service(finding.file) or finding.service
            if not service:
                # Репозиторные файлы (.github, корневые конфиги) не принадлежат
                # runtime-сервису, поэтому для них нельзя выдумывать dynamic-проверку.
                report = _build_static_finding_report(
                    finding,
                    target,
                    scoring_review=scoring_reviews.get(finding.id),
                    reason=(
                        "The finding belongs to the repository rather than a discovered "
                        "runtime service, so no sandbox action was selected."
                    ),
                )
                report.stop_reason = "missing_capability"
                report_path = reports_dir / f"{index:03d}-{_safe_name(finding.id)}.json"
                report_path.write_text(
                    report.model_dump_json(indent=2) + "\n",
                    encoding="utf-8",
                )
                reports.append(report)
                report_paths[report.finding_id] = str(report_path)
                progress.finding_finished(
                    finding_id=finding.id,
                    status=report.status,
                )
                print("  status=inconclusive capability=none context=repository")
                continue

            unsupported_reason = _unsupported_verification_reason(finding_profile, finding)
            if unsupported_reason is not None:
                report = _build_static_finding_report(
                    finding,
                    target,
                    scoring_review=scoring_reviews.get(finding.id),
                    reason=unsupported_reason,
                )
                report.stop_reason = ("unsupported_runtime" if "unsupported in the pinned Docker" in unsupported_reason
                                      else "missing_capability")
                persist_agent_trace(output_dir, finding.id, {"finding": finding,
                    "status": report.status, "stop_reason": report.stop_reason})
                report_path = reports_dir / f"{index:03d}-{_safe_name(finding.id)}.json"
                report_path.write_text(
                    report.model_dump_json(indent=2) + "\n",
                    encoding="utf-8",
                )
                reports.append(report)
                report_paths[report.finding_id] = str(report_path)
                progress.finding_finished(
                    finding_id=finding.id,
                    status=report.status,
                )
                print("  status=inconclusive capability=none context=unmapped")
                continue

            state = build_real_initial_state(
                findings_path=findings_path,
                target_root=target,
                architecture_path=architecture,
                target_profile=finding_profile,
                architecture_overrides_path=architecture_overrides,
                finding_id=finding.id,
                finding_override=finding,
                max_iterations=args.max_iterations,
            )
            if runtime_services is not None:
                # Все действия одного CI-запуска используют уже поднятую sandbox-сессию.
                state["runtime_services"] = runtime_services
            # PR metadata добавляем поверх source artifact, не переписывая его
            state["finding"] = finding
            state["scoring_review"] = scoring_reviews.get(finding.id)
            if finding_profile.b06_verification is not None:
                from agent.b06_lab import B06GraphLab
                from security.verification_binding import resolve_binding
                bound = resolve_binding(finding_profile, finding)
                if bound.binding is not None:
                    with B06GraphLab(finding_profile, finding, output_dir / "b06-runtime" / str(index)) as executor:
                        runtime = executor._verification_runtime
                        state["target_profile"] = runtime.profile
                        state["runtime_services"] = runtime.runtime_map()
                        result = graph.invoke(state)
                else:
                    result = graph.invoke(state)
            elif runtime_services is None or settings.agent_mode != "llm":
                result = graph.invoke(state)
            else:
                # Один finding может пройти несколько итерации, workspace должен пережить их все.
                with ManagedAgentLab(finding_profile, runtime_services):
                    result = graph.invoke(state)
            check_cancelled()
            persist_agent_trace(output_dir, finding.id, result)
            report = result["final_report"]
            pipeline_errors.extend(report.workflow_errors)
            report_path = reports_dir / f"{index:03d}-{_safe_name(finding.id)}.json"
            report_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
            reports.append(report)
            report_paths[report.finding_id] = str(report_path)
            progress.finding_finished(finding_id=finding.id, status=report.status)

            print(
                "  "
                f"status={report.status} "
                f"capability={report.verification.capability or 'none'} "
                f"context={report.context_priority.level if report.context_priority else 'N/A'}"
            )
            if args.full_reports:
                print()
                print(render_final_report(report))
        # Падение одного финдинга не прячет остальные, но гейт это обязательно увидит
        except RunCancelled:
            raise
        except Exception as exc:
            logger.exception("Finding workflow failed: %s", finding.id)
            error = error_from_exception(
                exc,
                layer="pipeline",
                public_message=f"Finding workflow failed: {finding.id}",
            )
            pipeline_errors.append(error)
            # Bootstrap/context cleanup failures must also retain a row in the
            # result set. A failed cleanup invalidates a previous terminal claim.
            from agent.recovery import stop_update
            failed_state = dict(result or state or {"finding": finding})
            failed_state.update(stop_update(failed_state, "workflow_failure", error.message))
            failed_state["scoring_review"] = None
            failed_state["workflow_errors"] = [*failed_state.get("workflow_errors", []), error]
            try:
                report = build_final_report(failed_state)
                persist_agent_trace(output_dir, finding.id, failed_state)
                report_path = reports_dir / f"{index:03d}-{_safe_name(finding.id)}.json"
                report_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
                reports = [item for item in reports if item.finding_id != finding.id]
                reports.append(report)
                report_paths[finding.id] = str(report_path)
            except (OSError, ValueError, TypeError) as storage_exc:
                pipeline_errors.append(error_from_exception(
                    storage_exc, layer="storage", public_message="Failed to persist finding failure report"))
            progress.finding_finished(finding_id=finding.id, status="error")
            print(f"  ERROR [{error.code}/{error.layer}]: {error.message}")

    check_cancelled()
    if verification_profiles:
        (output_dir / "verification-routing.json").write_text(
            json.dumps(routing_records, indent=2) + "\n", encoding="utf-8")
    gate = evaluate_gate(reports, errors=pipeline_errors, report_paths=report_paths)
    _write_index(output_dir, reports, report_paths)
    _write_gate(output_dir, gate)
    _print_gate(gate)
    return gate.exit_code


def _append_scout_findings(
    findings, discovery, *, output_dir=None, service_resolver=None, progress=None,
):
    """Scout дает дополнительные гипотезы, но сбой LLM не ломает SAST pipeline."""
    if settings.agent_mode != "llm" or discovery is None:
        return findings
    if progress is not None:
        progress.scout(status="running", max_turns=settings.scout_max_turns)
    try:
        client = FallbackLLMAgentModel.from_settings(settings).client
        try:
            source_map = build_express_source_map(discovery, include_oracle_controllers=False,
                                                  include_vulnerability_regions=False)
        except (OSError, TypeError, ValueError) as exc:
            source_map = None
            logger.warning("Express source map unavailable: %s", type(exc).__name__)
        scout = RepositoryScout(
            client, max_turns=settings.scout_max_turns,
            max_source_chars=settings.scout_max_source_chars,
            max_candidates=settings.scout_max_candidates,
            wall_clock_seconds=settings.scout_wall_clock_seconds,
            schedule_mode=settings.scout_schedule_mode,
            check_cancelled=check_cancelled,
            on_progress=(
                lambda event: progress.scout(
                    status="running", turn=event["turn"], max_turns=event["max_turns"],
                    reviewed_files=event["reviewed_files"],
                    candidates=event["candidate_count"],
                )
                if progress is not None else None
            ),
        )
        batch = scout.scout(discovery, source_map=source_map)
    except (LLMUnavailableError, ValueError, OSError) as exc:
        logger.warning("Repository scout unavailable: %s", type(exc).__name__)
        if progress is not None:
            progress.scout(
                status="done", candidates=0, stop_reason="model_unavailable",
            )
        return findings
    candidates = validate_scout_candidates(batch.candidates, discovery)
    route_links = (
        link_candidates_to_routes(candidates, source_map)
        if source_map is not None else []
    )
    merged, duplicates = merge_scout_candidates(
        findings, candidates, service_resolver=service_resolver,
        repository_root=discovery.repository_root,
    )
    audit = getattr(scout, "audit", {})
    original_ids = {item.id for item in findings}
    added = sum(not original_ids.intersection(
        {item.id, *(item.provenance.aliases if item.provenance else [])},
    ) for item in merged)
    audit.update(merged_candidates=added, duplicates=duplicates,
                 queue_before=len(findings), queue_after=len(merged))
    audit["sast_vs_sast_scout"] = {
        "sast_queue": len(findings), "combined_queue": len(merged),
        "new_scout_candidates": added, "duplicates": duplicates,
        "scope": "candidate_discovery_only_not_precision_recall_or_confirmed",
    }
    if source_map is not None:
        audit["route_candidate_links"] = {
            "candidates": len(route_links),
            "mapped": sum(item["binding_status"] != "unmapped" for item in route_links),
            "ambiguous": sum(item["binding_status"] == "ambiguous" for item in route_links),
            "authorization_assessed": False,
        }
    if source_map is not None:
        audit["express_source_map"] = {
            "analyzed_files": len(source_map.analyzed_files),
            "routes": len(source_map.routes),
            "middleware_mounts": len(source_map.middleware_mounts),
            "dynamic_routes": source_map.dynamic_routes,
            "omitted_routes": source_map.omitted_routes,
            "omitted_middleware_mounts": source_map.omitted_middleware_mounts,
            "unsupported_files": source_map.unsupported_files,
        }
    if progress is not None:
        progress.scout(
            status="done", candidates=len(candidates),
            reviewed_files=len({item["file"] for item in audit.get("reviewed_ranges", [])}),
            stop_reason=audit.get("stop_reason"),
        )
    if output_dir is not None:
        destination = Path(output_dir) / "scout"
        destination.mkdir(parents=True, exist_ok=True)
        if source_map is not None:
            (destination / "express-source-map.json").write_text(
                source_map.model_dump_json(indent=2), encoding="utf-8",
            )
            (destination / "candidate-route-links.json").write_text(
                json.dumps(route_links, ensure_ascii=False, indent=2), encoding="utf-8",
            )
        (destination / "summary.json").write_text(
            json.dumps(audit, ensure_ascii=False, indent=2), encoding="utf-8",
        )
        (destination / "candidates.json").write_text(
            batch.model_dump_json(indent=2), encoding="utf-8",
        )
        (destination / "merged-findings.json").write_text(
            json.dumps([item.model_dump(mode="json") for item in merged],
                       ensure_ascii=False, indent=2), encoding="utf-8",
        )
    print(f"Scout: {len(candidates)} source-backed candidates, "
          f"{duplicates} duplicates, stop={audit.get('stop_reason', 'unknown')}")
    return merged


def _build_static_finding_report(
    finding,
    target: Path,
    *,
    reason: str,
    scoring_review=None,
) -> FinalReport:
    """Собираем auditable report когда trusted active verification недоступен"""

    code = LocalCodeReader(target).read_code(
        finding.file,
        finding.line_start,
        finding.line_end,
    )
    gate = classify_finding_gate(
        finding_id=finding.id,
        status="inconclusive",
        context_level=None,
        cvss_severity=None,
        pr_classification=(
            finding.pr_context.classification
            if finding.pr_context is not None
            else None
        ),
    )
    from schemas.architecture import ArchitectureContext
    from scoring.review import resolve_review
    from scoring.service import ScoringService
    assessment, refs, severity, resolution = resolve_review(finding, target, scoring_review)
    context = ArchitectureContext(service=finding.service or "unknown")
    cvss, priority = ScoringService().score(
        finding, context, assessment=assessment, trusted_evidence_refs=refs,
    )
    return FinalReport(
        finding_id=finding.id,
        finding=ReportFinding(
            id=finding.id,
            source=finding.source,
            rule_id=finding.rule_id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            service=finding.service,
            file=finding.file,
            line_start=finding.line_start,
            line_end=finding.line_end,
            pr_context=finding.pr_context,
            provenance=finding.provenance,
        ),
        status="inconclusive",
        analysis_summary=(
            "SAST recorded a source finding. It is preserved as a static observation "
            "and was not converted into an unsupported runtime claim."
        ),
        code_context=code.content,
        architecture_context=context,
        cvss=cvss,
        context_priority=priority,
        technical_severity=severity,
        scoring_review_resolution=resolution,
        verification=VerificationSummary(
            validator_decision="not_run",
            evidence_count=0,
            decision_basis="workflow_state",
        ),
        ci_gate_impact=CIGateImpact(
            effect=gate.effect,
            category=gate.category,
            reason=gate.reason,
        ),
        explanation=reason,
        limitations=[
            "The static SAST observation was not confirmed by a runtime capability.",
            "Context Priority is provisional; deployment context was not resolved.",
            *resolution.diagnostics,
        ],
        next_step=(
            "Add the required trusted artifact mapping or review the source finding, "
            "then rerun the analysis."
        ),
        iterations=0,
    )


def _unsupported_verification_reason(profile: TargetProfile, finding) -> str | None:
    """Объясняем почему capability нельзя привязать к trusted данным профиля"""

    rule_id = finding.rule_id.lower()
    if profile.b06_verification is not None:
        from sast.identity import rule_family
        if (rule_family(finding.rule_id) == "code-injection"
                and finding.file in {"routes/userProfile.ts", "routes/updateUserProfile.ts"}):
            return ("B06 code evaluation is unsupported in the pinned Docker configuration: "
                    "usernameXssChallenge is disabled under auto safety mode. No runtime marker was executed.")
    required_paths: list[tuple[str, str | None]] = []
    required_roles: list[str] = []
    required_metadata: list[str] = []

    if rule_id.startswith(
        (
            "dockerfile.security.missing-user",
            "dockerfile.security.last-user-is-root",
        )
    ):
        required_paths.append((finding.file, "dockerfile"))
    elif "unvalidated-password" in rule_id:
        required_paths.append((finding.file, "python"))
    elif "react-dangerouslysetinnerhtml" in rule_id:
        required_paths.append((finding.file, None))
        required_roles.extend(
            [
                "react_html_flow.model",
                "react_html_flow.serializer",
                "react_html_flow.view",
            ]
        )
        required_metadata.append("react_html_flow.field")
    else:
        return None

    missing: list[str] = []
    for path, kind in required_paths:
        try:
            profile.artifact_id_for_path(path, kind=kind)
        except ValueError:
            missing.append(f"artifact:{path}")
    for role in required_roles:
        try:
            profile.artifact_id_for_role(role)
        except ValueError:
            missing.append(f"role:{role}")
    for key in required_metadata:
        if not profile.metadata.get(key):
            missing.append(f"metadata:{key}")

    if not missing:
        return None
    return (
        "The target profile does not map the trusted inputs required by this "
        f"specialized verification capability ({', '.join(missing)}). The SAST "
        "finding remains inconclusive; Validator and Executor were not bypassed."
    )


def main() -> int:
    return run_pipeline(_parse_args())


def _resolve_findings(
    *,
    existing_findings: str | None,
    target: Path,
    sast_config: str,
    output_dir: Path,
    service_resolver: Callable[[str], str | None],
) -> Path:
    if existing_findings:
        path = Path(existing_findings).expanduser()
        from sast.identity import deduplicate_findings, normalize_finding

        findings = JsonFindingRepository(path).list_findings()
        normalized, _ = deduplicate_findings([
            normalize_finding(item, repository_root=target, service_resolver=service_resolver)
            for item in findings
        ])
        output_dir.mkdir(parents=True, exist_ok=True)
        normalized_path = output_dir / "findings.json"
        if normalized_path.resolve() == path.resolve():
            normalized_path = output_dir / "normalized-findings.json"
        normalized_path.write_text(json.dumps(
            [item.model_dump(mode="json") for item in normalized], ensure_ascii=False, indent=2,
        ), encoding="utf-8")
        print(f"SAST: using existing normalized findings: {path}")
        return normalized_path

    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"SAST: scanning with Semgrep config={sast_config}")
    profile = None
    target_snapshot_before = None
    config_files: str | list[str] = sast_config
    if Path(sast_config).is_file():
        try:
            profile = load_scan_profile(sast_config)
        except ValueError as exc:
            if "Not a supported CFT Semgrep profile" not in str(exc):
                raise
        else:
            config_files = profile["config_files"]
            target_snapshot_before = validate_target_snapshot(target, profile["target_commit"])
    scan = run_semgrep_scan(
        target,
        config=config_files,
        timeout_seconds=600,
        service_resolver=service_resolver,
    )

    raw_path = output_dir / "semgrep.json"
    findings_path = output_dir / "findings.json"
    summary_path = output_dir / "summary.json"
    raw_path.write_text(json.dumps(scan.raw, ensure_ascii=False, indent=2), encoding="utf-8")
    findings_path.write_text(
        json.dumps(
            [finding.model_dump(mode="json") for finding in scan.findings],
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    summary = {
        "total": len(scan.findings),
        "raw_total": sum(isinstance(item, dict) for item in scan.raw.get("results", [])),
        "duplicates": sum(isinstance(item, dict) for item in scan.raw.get("results", [])) - len(scan.findings),
        "normalization_version": "s02.v1",
        "by_severity": dict(
            sorted(
                Counter(
                    (finding.severity or "UNKNOWN").upper() for finding in scan.findings
                ).items()
            )
        ),
        "by_service": dict(
            sorted(Counter(finding.service or "unknown" for finding in scan.findings).items())
        ),
        "semgrep_errors": len(scan.raw.get("errors", []))
        if isinstance(scan.raw.get("errors", []), list)
        else 0,
        "scanner_warnings": [str(item) for item in scan.raw.get("errors", [])
                             if isinstance(item, dict)],
        "scanner_stderr": scan.stderr,
        "files_scanned": len(scan.raw.get("paths", {}).get("scanned", []))
        if isinstance(scan.raw.get("paths", {}), dict) else None,
        "files_skipped": sum(len(value) for value in scan.raw.get("paths", {}).get("skipped", {}).values())
        if isinstance(scan.raw.get("paths", {}).get("skipped", {}), dict) else None,
        "signal_types": dict(sorted(Counter(
            str(item.get("extra", {}).get("metadata", {}).get("signal", "code"))
            for item in scan.raw.get("results", []) if isinstance(item, dict)
        ).items())),
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    if profile is not None:
        import subprocess

        commit = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "HEAD"], capture_output=True,
            text=True, check=False, timeout=10,
        )
        coverage_diagnostics, fatal_diagnostics = classify_diagnostics(scan.raw)
        try:
            target_snapshot_after = validate_target_snapshot(target, profile["target_commit"])
        except ValueError as exc:
            target_snapshot_after = None
            fatal_diagnostics.append({"message": str(exc)})
        metadata = {
            "profile": profile["id"], "profile_version": profile["version"],
            "profile_path": profile["profile_path"],
            "semgrep_version_expected": profile["semgrep_version"],
            "semgrep_version_reported": scan.raw.get("version"),
            "target_commit_expected": profile.get("target_commit"),
            "target_commit_observed": commit.stdout.strip() if commit.returncode == 0 else None,
            "target_snapshot_before": target_snapshot_before,
            "target_snapshot_after": target_snapshot_after,
            "coverage_limitations": coverage_diagnostics,
            "fatal_scanner_diagnostics": fatal_diagnostics,
            "config_files": profile["config_files"],
            "config_sha256": profile["config_sha256"],
            "exclude": profile.get("exclude", []),
            "raw_result": str(raw_path), "normalized_findings": str(findings_path),
            "summary": str(summary_path),
        }
        validation_errors = []
        if profile.get("semgrep_version") != scan.raw.get("version"):
            validation_errors.append("Semgrep runtime version differs from profile pin")
        if profile.get("target_commit") and (
            commit.returncode != 0 or commit.stdout.strip() != profile["target_commit"]
        ):
            validation_errors.append("Target commit differs from profile pin")
        if (target_snapshot_before is None or target_snapshot_after is None
                or target_snapshot_before != target_snapshot_after):
            validation_errors.append("Target source snapshot changed during scan")
        if fatal_diagnostics:
            validation_errors.append("Semgrep reported fatal or unclassified diagnostics")
        metadata["validation_errors"] = validation_errors
        metadata["technically_valid"] = not validation_errors
        (output_dir / "manifest.json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        if validation_errors:
            raise SemgrepError("B02 SAST profile validation failed: " + "; ".join(validation_errors))
    print(f"SAST findings: {summary['total']} -> {findings_path}")
    return findings_path


def _write_index(
    output_dir: Path,
    reports: list[FinalReport],
    report_paths: dict[str, str],
) -> None:
    payload = [
        {
            "finding_id": report.finding_id,
            "status": report.status,
            "report_path": report_paths.get(report.finding_id),
        }
        for report in reports
    ]
    (output_dir / "reports-index.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_gate(output_dir: Path, gate: GateResult) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "gate.json").write_text(gate.model_dump_json(indent=2) + "\n", encoding="utf-8")


def _print_gate(gate: GateResult) -> None:
    print()
    print("=" * 72)
    print(f"CI/CD GATE: {gate.decision.upper()}")
    print("=" * 72)
    print(
        f"reports={gate.reports_total} confirmed={gate.confirmed} rejected={gate.rejected} "
        f"inconclusive={gate.inconclusive} policy_blocked={gate.policy_blocked}"
    )
    for reason in gate.reasons:
        print(f"- {reason}")
    for error in gate.errors:
        print(f"- stage error [{error.code}/{error.layer}]: {error.message}")

    if os.getenv("GITHUB_ACTIONS", "").lower() == "true":
        annotation = "error" if gate.decision == "fail" else "warning"
        if gate.decision != "pass":
            for reason in gate.reasons:
                print(f"::{annotation}::{reason}")
        for error in gate.errors:
            print(f"::error::[{error.code}/{error.layer}] {error.message}")

    print(f"exit_code={gate.exit_code}")


def _safe_name(value: str) -> str:
    safe = "".join(char if char.isalnum() or char in {"-", "_", "."} else "-" for char in value)
    return safe[:140].strip("-.") or "finding"


if __name__ == "__main__":
    raise SystemExit(main())
