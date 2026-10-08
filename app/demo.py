"""Presentation-sized runs through the real API and canonical CI pipeline.

Only the rule selection and exploration budgets differ from a full run. This is
not a benchmark or a replacement implementation of verification.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from threading import Lock

import uvicorn
from fastapi import HTTPException

from agent.llm import ProviderFailoverClient, parse_route_specs
from api.app import create_app
from api.registry import ApiTargetRegistry
from api.service import RunOrchestrator
from api.store import ApiStore
from app.ci_pipeline import run_ci_pipeline
from app.config import settings
from fix_verification.review import prepare_patch_review, validate_sequelize_search_proposal
from schemas.fix import PatchReviewArtifact

ROOT = Path(__file__).resolve().parent.parent
PROFILE = ROOT / "targets/juice-presentation.yaml"
RULES = ROOT / "docs/demo/semgrep.yaml"
PATCH_FINDING = "sequelize-injection.presentation:routes/search.ts:23"
PATCH_REVIEW_POLICY = "sequelize_search_review_v1"


def create_demo_app(service: RunOrchestrator, *, patch_client_factory=None):
    """Opt-in proposal endpoints. Never invoke the old host check runner."""
    app = create_app(service)
    patch_lock = Lock()

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
                (directory / "proposal.patch").write_text(artifact.proposal.unified_diff, encoding="utf-8")
            return artifact
        except KeyError as exc:
            raise HTTPException(404, "Confirmed SQL report not found") from exc
        except (ValueError, OSError) as exc:
            raise HTTPException(409, "Исходник или предложение не прошли проверку; патч не применялся") from exc
        except RuntimeError as exc:
            raise HTTPException(503, "Модель не вернула корректное предложение; патч не применялся") from exc
        finally:
            patch_lock.release()

    return app


def run_demo_pipeline(args: argparse.Namespace) -> int:
    """Keep demo scope explicit, and preserve all normal security boundaries."""
    if Path(args.profile).resolve() != PROFILE:
        raise ValueError("Presentation runner accepts only its registered demo profile")
    args.sast_config = str(RULES)
    saved = {
        key: getattr(settings, key)
        for key in (
            "scout_max_turns", "scout_max_candidates", "scout_wall_clock_seconds",
            "llm_reasoning_effort", "llm_max_output_tokens", "llm_timeout_seconds",
        )
    }
    settings.scout_max_turns = 2
    settings.scout_max_candidates = 4
    settings.scout_wall_clock_seconds = 60.0
    settings.llm_reasoning_effort = "low"
    settings.llm_max_output_tokens = 8192
    settings.llm_timeout_seconds = 55.0
    destination = Path(args.output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "demo-scope.json").write_text(json.dumps({
        "kind": "scoped_presentation_run",
        "full_benchmark": False,
        "sast_rules": ["sequelize-injection.presentation", "directory-listing.presentation"],
        "sast_config": "docs/demo/semgrep.yaml",
        "scout_max_turns": 2,
        "scout_max_candidates": 4,
        "requested_agent_mode": args.agent_mode,
        "model_routes": settings.llm_routes,
        "reasoning_effort": settings.llm_reasoning_effort,
        "max_output_tokens": settings.llm_max_output_tokens,
        "request_timeout_seconds": settings.llm_timeout_seconds,
        "max_iterations": args.max_iterations,
        "target_version": "20.2.0",
        "target_commit": "5658473cf8814459bf89000ce373b20ed0b4eb37",
        "note": "LLM attempts and actual fallback use are recorded separately in audit/.",
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        return run_ci_pipeline(args)
    finally:
        for key, value in saved.items():
            setattr(settings, key, value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if Path.cwd().resolve() != ROOT:
        raise SystemExit(f"Run from the repository directory: {ROOT}")
    registry = ApiTargetRegistry.from_profile_paths([PROFILE], trusted_root=ROOT / "targets")
    target = registry.get("juice-presentation").profile
    if target.repository_path is None or not target.repository_path.is_dir():
        raise SystemExit("Demo target is missing. See docs/demo/README.md to prepare it.")
    settings.agent_mode = "llm"
    # The old DeepSeek identifier returns Model not found on NSU; keep this
    # presentation route explicit without changing the user's main .env chain.
    settings.llm_routes = "nsu:Qwen3.8-27B"
    service = RunOrchestrator(
        registry=registry,
        store=ApiStore(ROOT / "api_data/presentation-2026-10-08.sqlite3"),
        artifact_root=ROOT / "artifacts/presentation-2026-10-08/runs",
        project_root=ROOT / "api_data/presentation-projects",
        pipeline_runner=run_demo_pipeline,
        max_workers=1,
    )
    uvicorn.run(create_demo_app(service), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
