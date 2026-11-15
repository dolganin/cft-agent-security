"""Prepare read-only reasoning input for bounded provider concurrency."""
from app.e2e_inputs import build_real_initial_state


def prefetch_reasoning(*, model, findings, profile, runtime_services, findings_path,
                       architecture, architecture_overrides, scoring_reviews,
                       max_iterations, progress, workers):
    from agent.nodes import load_context, score_finding
    from pipeline.cancellation import check_cancelled

    states = {}
    for finding in findings:
        check_cancelled()
        if not (profile.resolve_service(finding.file) or finding.service):
            continue
        try:
            state = build_real_initial_state(
                findings_path=findings_path, target_root=profile.repository_path,
                architecture_path=architecture, target_profile=profile,
                architecture_overrides_path=architecture_overrides,
                finding_id=finding.id, finding_override=finding, max_iterations=max_iterations,
            )
            state["runtime_services"] = runtime_services
            state["finding"] = finding
            state["scoring_review"] = scoring_reviews.get(finding.id)
            state.update(load_context(state))
            state.update(score_finding(state))
        except (OSError, ValueError, TypeError):
            # Leave context failure handling to the normal per-finding graph.
            continue
        states[finding.id] = state
    if states:
        progress.stage("reasoning", status="running",
                       detail=f"{len(states)} findings; up to {workers} parallel model requests")
        model.prefetch(list(states.values()), workers=workers)
        progress.stage("reasoning", status="done", detail=f"{len(states)} finding contexts prepared")
    return states
