"""R05/R06 integrated bounded campaign. No evaluator answers enter the producer."""
import json
import time
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from app.research_run import run_research
from discovery.express_routes import build_express_source_map
from discovery.service import ProjectDiscovery
from evidence.research_http_replay import replay_marker
from evidence.research_review import attach_source_review, review_source_claims
from pipeline.cancellation import check_cancelled
from pipeline.research_queue import ResearchQueue
from reporting.builder import build_final_report
from schemas.research_agent import ResearchLimits
from schemas.research_campaign import CampaignLimits
from tools.repository_source import RepositorySource


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def campaign(*, profile, configuration, client, output, sast=(), dast=(), limits=None, research_limits=None,
             http_review_registry=None, acceptance_require_script=False):
    limits, research_limits = limits or CampaignLimits(), research_limits or ResearchLimits(max_steps=8)
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError("A campaign never overwrites a saved run")
    started = time.monotonic()
    output.mkdir(parents=True)
    inventory = ProjectDiscovery().discover(profile.repository_path)
    source = RepositorySource(inventory)
    source_map = build_express_source_map(inventory, include_oracle_controllers=False)
    files = configuration.get("source_files", list(source.files))
    files = [p for p in files if p in source.files]
    if not files:
        raise ValueError("No approved application source")
    configuration = {**configuration, "source_files": files}
    queue = ResearchQueue(profile=profile, source_map=source_map, source_files=files,
                          preferred_families=limits.dev_preferred_families)
    http_review_registry = http_review_registry or {}
    queue.import_findings(sast, "sast")
    queue.import_findings(dast, "dast")
    write_json(output / "surface-map.json", source_map.model_dump(mode="json"))
    write_json(output / "manifest.json", {"schema": "cft.research.campaign.v1",
        "started_at": datetime.now(UTC).isoformat(), "limits": limits.model_dump(),
        "research_limits": research_limits.model_dump(), "source_files": files,
        "source_sha256": {p: sha256((profile.repository_path / p).read_bytes()).hexdigest() for p in files},
        "source_review_protocols": ["weak_digest_call.v1"],
        "source_review_scope": "source condition only; not runtime exploitability",
        "http_review_protocols": [spec.public() for spec, _ in http_review_registry.values()],
        "http_review_status": "enabled" if http_review_registry else "requires private operator-owned marker registry/factory",
        "benchmark_measurement": False, "repetitions": 1, "reproducibility": "not_measured"})
    calls = actions = 0
    model_io = observation_bytes = write_bytes = 0
    ledgers, reports, reviews, runs = [], [], [], []
    stop = "queue_exhausted"
    for ordinal in range(limits.max_questions):
        check_cancelled()
        remaining_wall = int(limits.wall_seconds - (time.monotonic() - started))
        remaining_calls, remaining_actions = limits.max_model_calls - calls, limits.max_actions - actions
        remaining_io = limits.max_model_io_bytes - model_io
        remaining_observation = limits.max_observation_bytes - observation_bytes
        if min(remaining_wall, remaining_calls, remaining_actions) < 1 or remaining_io < 4096 or remaining_observation < 65536:
            stop = "campaign_budget_exhausted"
            break
        question = queue.next_question()
        if question is None:
            break
        related = source_map.for_context({question.finding.file}, limit=12)
        related["source_priority_index"] = [p for p in files if p.startswith(("routes/", "lib/", "models/"))][:48]
        related["http_proof_specs"] = [spec.public() for spec, _ in http_review_registry.values()]
        if acceptance_require_script:
            related["dev_acceptance_objective"] = "Demonstrate a self-authored Python/Node source-inspection script and an ordinary non-mutating allowed target_http observation before finishing. Script stdout and a successful HTTP response are NOT security verdicts. Use read/write/run tools, not host execution."
        scoped_limits = research_limits.model_copy(update={
            "max_steps": min(research_limits.max_steps, remaining_actions),
            "max_model_calls": min(research_limits.max_model_calls, remaining_calls),
            "max_model_io_bytes": min(research_limits.max_model_io_bytes, remaining_io),
            "max_observation_bytes": min(research_limits.max_observation_bytes, remaining_observation),
            "max_write_bytes": max(0, min(research_limits.max_write_bytes, limits.max_write_bytes - write_bytes)),
            "wall_seconds": min(research_limits.wall_seconds, remaining_wall)})
        directory = output / "questions" / str(ordinal)
        state, summary = run_research(profile=profile, configuration=configuration, finding=question.finding,
            client=client, output=directory, limits=scoped_limits, surface_context=related)
        progress, scope = state["research_progress"], state["research_scope"]
        calls += summary["model_calls"]
        actions += summary["actions"]
        model_io += progress.model_io_bytes
        observation_bytes += progress.observation_bytes
        write_bytes += progress.write_bytes
        ledgers.append(progress.ledger)
        queue.complete(question, failed=bool(state.get("workflow_errors")))
        queue.import_candidates(progress.candidates)
        independent = review_source_claims(root=profile.repository_path, scope=scope,
            progress=progress, output=output / "reviews" / str(ordinal))
        reviews.extend(independent)
        for claim in progress.http_claims:
            spec, factory = http_review_registry[claim.spec_id]
            original_reads = {item.action_id: item for item in progress.ledger}
            if any(original_reads[ref].observation.get("path") != spec.probe_path for ref in claim.observation_refs):
                reviews.append({"status": "review_pending", "reason": "Claim references a different HTTP observation"})
                continue
            reviews.append(replay_marker(claim=claim, spec=spec, generation_factory=factory,
                output=output / "http-reviews" / f"{ordinal}-{len(reviews)}",
                original_container_ids=[service.container_id for service in scope.services.values()],
                source_snapshot=scope.source_snapshot, image_ids={spec.service: scope.services[spec.service].image_id}))
        state = attach_source_review(state, independent, output / "reviews" / str(ordinal))
        report = build_final_report(state)
        reports.append({"question_id": question.id, "is_candidate": question.is_candidate,
                        "report": report.model_dump(mode="json")})
        # A new cause discovered during another question owns its own report;
        # don't attribute a crypto proof to the original unrelated SAST finding.
        already_reported = {r["report"]["finding_id"] for r in reports}
        for finding in queue.findings:
            if finding.id in already_reported:
                continue
            derived = attach_source_review({**state, "finding": finding, "status": "inconclusive",
                "cvss": None, "context_priority": None, "technical_severity": None,
                "scoring_review": None, "scoring_review_resolution": None}, independent, output / "reviews" / str(ordinal))
            if derived["status"] not in {"confirmed", "rejected"}:
                continue
            derived_report = build_final_report(derived)
            reports.append({"question_id": finding.id, "is_candidate": True,
                "discovered_during": question.id, "report": derived_report.model_dump(mode="json")})
            related_question = next((q for q in queue.questions if q.id == finding.id), None)
            if related_question is not None:
                queue.complete(related_question)
        runs.append({"question_id": question.id, "summary": summary})
        write_json(output / "questions.json", [q.model_dump(mode="json") for q in queue.questions])
        write_json(output / "raw-observations.json", queue.raw)
        write_json(output / "findings.json", [f.model_dump(mode="json") for f in queue.findings])
        write_json(output / "reports.json", reports)
        write_json(output / "reviews.json", reviews)
        write_json(output / "coverage.json", queue.coverage(ledgers))
        if state.get("stop_reason") == "model_failure":
            stop = "model_failure"
            break
    else:
        stop = "question_budget_exhausted"
    manifest = json.loads((output / "manifest.json").read_text())
    integrity = all(sha256((profile.repository_path / p).read_bytes()).hexdigest() == digest
                    for p, digest in manifest["source_sha256"].items())
    summary = {"schema": "cft.research.campaign.result.v1", "runs": runs,
        "model_calls": calls, "actions": actions, "questions_researched": len(runs),
        "model_io_reserved_bytes": model_io, "observation_bytes": observation_bytes, "write_bytes": write_bytes,
        "candidate_count": len(queue.findings), "review_counts": {status: sum(r["status"] == status for r in reviews)
            for status in ("confirmed", "rejected", "review_pending")},
        "stop_reason": stop, "source_unchanged": integrity,
        "cleanup_verified": all(r["summary"]["cleanup_verified"] for r in runs),
        "elapsed_seconds": round(time.monotonic() - started, 3), "benchmark_measurement": False,
        "source_confirmations_are_not_runtime_exploits": True}
    write_json(output / "summary.json", summary)
    write_json(output / "rejected-inputs.json", queue.rejections)
    write_json(output / "coverage.json", queue.coverage(ledgers))
    if not integrity:
        raise RuntimeError("Campaign source integrity changed; result invalid")
    return summary


def main():
    import argparse

    from agent.llm_model import FallbackLLMAgentModel
    from app.config import settings
    from schemas.finding import Finding
    from schemas.research_campaign import RuntimeScannerObservation
    from schemas.target import TargetProfile

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--operator-config", type=Path, required=True)
    parser.add_argument("--sast", type=Path)
    parser.add_argument("--dast", type=Path)
    parser.add_argument("--limits", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    client = FallbackLLMAgentModel.from_settings(settings).client
    if len(client.routes) != 1:
        raise ValueError("Select one explicit model route for a bounded campaign")
    profile = TargetProfile.from_yaml(args.profile, repository_path_override=args.checkout)
    sast = [Finding.model_validate(x) for x in json.loads(args.sast.read_text())] if args.sast else []
    dast = [(RuntimeScannerObservation if "endpoint" in x else Finding).model_validate(x)
            for x in json.loads(args.dast.read_text())] if args.dast else []
    limits = CampaignLimits.model_validate(json.loads(args.limits.read_text())) if args.limits else CampaignLimits()
    print(json.dumps(campaign(profile=profile, configuration=json.loads(args.operator_config.read_text()),
        client=client, output=args.output, sast=sast, dast=dast, limits=limits), indent=2))


if __name__ == "__main__":
    main()
