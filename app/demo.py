"""Presentation-sized runs through the real API and canonical CI pipeline.

Only the rule selection and exploration budgets differ from a full run. This is
not a benchmark or a replacement implementation of verification.
"""
from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from threading import Lock

from fastapi import HTTPException

from agent.llm import ProviderFailoverClient, parse_route_specs
from api.app import create_app
from api.service import RunOrchestrator
from app.ci_pipeline import run_ci_pipeline
from app.config import settings
from fix_verification.review import prepare_patch_review, validate_sequelize_search_proposal
from fix_verification.service import FixVerificationService
from schemas.fix import FixVerificationArtifact, PatchReviewArtifact

ROOT = Path(__file__).resolve().parent.parent
PROFILE = ROOT / "targets/juice-presentation.yaml"
RULES = ROOT / "docs/demo/semgrep.yaml"
ORDER_PROFILE = ROOT / "targets/demo-order-store.yaml"
ORDER_RULES = ROOT / "docs/demo/order-store-semgrep.yaml"
ORDER_TEMPLATE = ROOT / "demo-target/order-store"
PATCH_FINDING = "sequelize-injection.presentation:routes/search.ts:23"
PATCH_REVIEW_POLICY = "sequelize_search_review_v1"


def create_demo_app(
    service: RunOrchestrator,
    *,
    patch_client_factory=None,
    fix_service=None,
    order_store_preview_status: Callable[[], dict[str, str]] | None = None,
    on_shutdown: Callable[[], None] | None = None,
):
    """Demo artifacts remain separate from the original reports and CI Gate."""
    app = create_app(service, on_shutdown=on_shutdown)
    patch_lock = Lock()

    @app.get("/demo/order-store/status")
    def get_order_store_status():
        if order_store_preview_status is None:
            return {"status": "unavailable", "url": "http://127.0.0.1:8090"}
        return order_store_preview_status()

    def selected_run(run_id):
        try:
            run = service.get_run(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        if run.target_id != "juice-presentation" or run.status != "completed":
            raise HTTPException(409, "Нужен завершенный демонстрационный прогон")
        return service.store.artifact_dir(run_id)

    @app.get("/demo/runs/{run_id}/patch-proposal", response_model=PatchReviewArtifact | None)
    def get_patch(run_id: str):
        destination = selected_run(run_id) / "patch-review.json"
        if not destination.is_file():
            return None
        artifact = PatchReviewArtifact.model_validate_json(destination.read_text(encoding="utf-8"))
        if artifact.validation_policy != PATCH_REVIEW_POLICY:
            return artifact.model_copy(update={
                "status": "rejected", "validation_detail": "Требуется повторное ревью формата SQL-параметров.",
            })
        return artifact

    @app.post("/demo/runs/{run_id}/patch-proposal", response_model=PatchReviewArtifact)
    def propose_patch(run_id: str):
        directory = selected_run(run_id)
        if not patch_lock.acquire(blocking=False):
            raise HTTPException(409, "Предложение уже готовится")
        try:
            previous = get_patch(run_id)
            if previous is not None and previous.validation_policy == PATCH_REVIEW_POLICY:
                return previous
            report = service.get_report(run_id, PATCH_FINDING)
            profile = service.registry.get("juice-presentation").profile
            if profile.repository_path is None or report.finding.file != "routes/search.ts":
                raise ValueError("Demo source binding is unavailable")
            client = patch_client_factory(directory) if patch_client_factory else ProviderFailoverClient(
                routes=parse_route_specs("nsu:Qwen3.8-27B"),
                credentials=settings.llm_provider_credentials(),
                timeout_seconds=55, max_output_tokens=4096, reasoning_effort="low",
                diagnostics_path=directory / "audit/patch-llm-attempts.jsonl",
            )
            artifact = prepare_patch_review(
                client=client, report=report, repository=profile.repository_path,
                run_id=run_id, editable_start=20, editable_end=23,
                proposal_guard=validate_sequelize_search_proposal,
                validation_policy=PATCH_REVIEW_POLICY,
                trusted_guidance=(
                    "Target uses Sequelize v6. Preserve the SELECT list, deletedAt filter, ORDER BY and LIKE wildcards. "
                    "Modify ONLY the sequelize.query line, keep surrounding input handling unchanged. "
                    "Use :criteria in SQL with { replacements: { criteria: `%${criteria}%` } }. "
                    "Do not mix :parameters with bind; bind uses $parameters instead. "
                    "Reference: https://sequelize.org/docs/v6/core-concepts/raw-queries/"
                ),
            )
            # Only application-resolved artifact paths, never model/caller paths.
            destination = directory / "patch-review.json"
            if destination.is_file():
                history = directory / "patch-reviews"
                history.mkdir(exist_ok=True)
                (history / f"{previous.id}.json").write_text(previous.model_dump_json(indent=2), encoding="utf-8")
            temporary = directory / f".{artifact.id}.json"
            temporary.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
            temporary.replace(destination)
            if artifact.status == "ready_for_review":
                (directory / "proposal.patch").write_bytes(artifact.proposal.unified_diff.encode("utf-8"))
            return artifact
        except KeyError as exc:
            raise HTTPException(404, "Confirmed SQL report not found") from exc
        except (ValueError, OSError) as exc:
            raise HTTPException(409, "Исходник или предложение не прошли проверку; патч не применялся") from exc
        except RuntimeError as exc:
            raise HTTPException(503, "Модель не вернула корректное предложение; патч не применялся") from exc
        finally:
            patch_lock.release()

    @app.get("/demo/runs/{run_id}/fix-verification", response_model=FixVerificationArtifact | None)
    def get_fix(run_id: str):
        path = selected_run(run_id) / "fix-verification.json"
        return FixVerificationArtifact.model_validate_json(path.read_text(encoding="utf-8")) if path.is_file() else None

    @app.post("/demo/runs/{run_id}/fix-verification", response_model=FixVerificationArtifact)
    def verify_fix(run_id: str):
        directory = selected_run(run_id)
        if not patch_lock.acquire(blocking=False):
            raise HTTPException(409, "Проверка или подготовка патча уже выполняется")
        try:
            review = get_patch(run_id)
            if review is None or review.status != "ready_for_review" or review.run_id != run_id:
                raise HTTPException(409, "Требуется проверенное предложение патча")
            report = service.get_report(run_id, PATCH_FINDING)
            profile = service.registry.get("juice-presentation").profile
            result = (fix_service or FixVerificationService()).verify(
                report=report, review=review, profile=profile, artifact_directory=directory,
            )
            path = directory / "fix-verification.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(result.model_dump_json(indent=2), encoding="utf-8")
            temporary.replace(path)
            return result
        finally:
            patch_lock.release()

    return app


def run_demo_pipeline(args: argparse.Namespace) -> int:
    """Keep demo scope explicit, and preserve all normal security boundaries."""
    selected_profile = Path(args.profile).resolve()
    if selected_profile == PROFILE:
        rules = RULES
        demo_target = "juice-presentation"
        scout_turns, scout_candidates, scout_seconds = 2, 4, 60.0
        target_details = {
            "target_version": "20.2.0",
            "target_commit": "5658473cf8814459bf89000ce373b20ed0b4eb37",
            "sast_rules": ["sequelize-injection.presentation", "directory-listing.presentation"],
        }
    elif selected_profile == ORDER_PROFILE:
        rules = ORDER_RULES
        demo_target = "demo-order-store"
        scout_turns, scout_candidates, scout_seconds = 1, 4, 18.0
        target_details = {
            "target_version": "1.0",
            "target_commit": None,
            "sast_rules": [
                "demo-sql-injection.search",
                "demo-idor.order-read",
                "demo-sql-injection.authentication",
                "demo-file-exposure.directory-listing",
            ],
            "scope_note": "Four registered demo cases; not a benchmark or broad project audit.",
        }
    else:
        raise ValueError("Presentation runner accepts only its registered demo profile")
    args.sast_config = str(rules)
    args.coalesce_bound_scout = demo_target == "demo-order-store"
    args.reasoning_prefetch_workers = 2 if demo_target == "demo-order-store" else 1
    saved = {
        key: getattr(settings, key)
        for key in (
            "scout_max_turns", "scout_max_candidates", "scout_wall_clock_seconds",
            "llm_reasoning_effort", "llm_max_output_tokens", "llm_timeout_seconds",
            "policy_file", "llm_routes",
        )
    }
    try:
        settings.scout_max_turns = scout_turns
        settings.scout_max_candidates = scout_candidates
        settings.scout_wall_clock_seconds = scout_seconds
        settings.llm_reasoning_effort = "low"
        settings.llm_max_output_tokens = 4096 if demo_target == "demo-order-store" else 8192
        settings.llm_timeout_seconds = 15.0 if demo_target == "demo-order-store" else 55.0
        if demo_target == "demo-order-store":
            from app.setup import configured_demo_routes

            settings.llm_routes = configured_demo_routes(settings)
            settings.policy_file = ROOT / "policies/demo-order-store.yaml"
        destination = Path(args.output_dir)
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "demo-scope.json").write_text(json.dumps({
            "kind": "scoped_presentation_run",
            "full_benchmark": False,
            **target_details,
            "target_id": demo_target,
            "sast_config": rules.relative_to(ROOT).as_posix(),
            "scout_max_turns": scout_turns,
            "scout_max_candidates": scout_candidates,
            "requested_agent_mode": args.agent_mode,
            "model_routes": settings.llm_routes,
            "reasoning_effort": settings.llm_reasoning_effort,
            "max_output_tokens": settings.llm_max_output_tokens,
            "request_timeout_seconds": settings.llm_timeout_seconds,
            "policy_file": str(settings.policy_file),
            "max_iterations": args.max_iterations,
            "compact_registered_reasoning": demo_target == "demo-order-store",
            "coalesce_bound_scout": args.coalesce_bound_scout,
            "reasoning_prefetch_workers": args.reasoning_prefetch_workers,
            "note": "LLM attempts and actual fallback use are recorded separately in audit/.",
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        if demo_target == "demo-order-store" and (args.agent_mode or settings.agent_mode) == "llm":
            from agent.compact_model import CompactRegisteredAgentModel
            from agent.model import reasoning_model_context

            model = CompactRegisteredAgentModel.from_settings(settings)
            model.client.diagnostics_path = destination / "audit/llm-attempts.jsonl"
            with reasoning_model_context(model):
                return run_ci_pipeline(args)
        return run_ci_pipeline(args)
    finally:
        for key, value in saved.items():
            setattr(settings, key, value)


if __name__ == "__main__":
    raise SystemExit("Отдельный демосервер удален. Запустите cft-security-api.")
