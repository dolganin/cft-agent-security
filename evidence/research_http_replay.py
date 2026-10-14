"""General marker-disclosure replay on two independently provisioned generations."""
import json
from hashlib import sha256
from pathlib import Path

from app.research_plan import execute_plan
from executor.sandbox_audit import calculate_sha256_digest
from schemas.action import ActionProposal
from schemas.research import ResearchScope


def audit_observations(output, rows):
    audit = [json.loads(line) for line in (output / "audit.jsonl").read_text().splitlines()]
    observations = []
    for row in rows:
        action = ActionProposal.model_validate(row["action"])
        execution = row["execution"]
        if not row["validation"]["approved"] or not execution or execution["status"] != "completed":
            raise ValueError("Replay action not approved/completed")
        stored = json.loads((output / "evidence" / (execution["evidence_ref"] + ".json")).read_text())
        matches = [x for x in audit if x["run_id"] == execution["run_id"] and x["action_id"] == action.id]
        payload = {k: v for k, v in stored.items() if k not in {"id", "type", "created_at"}}
        if (len(matches) != 1 or matches[0]["evidence_digest"] != calculate_sha256_digest(payload)
                or matches[0]["proposal_digest"] != calculate_sha256_digest(action.model_dump())
                or stored.get("research_binding") != action.research_binding.model_dump(mode="json")):
            raise ValueError("Independent replay audit mismatch")
        observations.append(json.loads(stored["stdout"])["observation"])
    return observations


def marker_trial(observations, spec):
    if len(observations) != 4:
        return "review_pending"
    before, negative, probe, after = observations
    marker = spec.marker.get_secret_value()
    if len(marker) < 12 or not all(x.get("redirect_followed") is False for x in observations):
        return "review_pending"
    if any(x.get("status_code") != 200 or marker not in x.get("body", "")
           or x.get("role_handle") != spec.owner_role for x in (before, after)):
        return "review_pending"
    if (negative.get("status_code") not in spec.expected_denial_statuses
            or marker in negative.get("body", "") or negative.get("role_handle") is not None
            or negative.get("body_truncated") or probe.get("role_handle") is not None):
        return "review_pending"
    if probe.get("status_code") == 200 and marker in probe.get("body", ""):
        return "confirmed"
    if probe.get("status_code") in spec.expected_denial_statuses and not probe.get("body_truncated"):
        return "rejected"
    return "review_pending"


def replay_marker(*, claim, spec, generation_factory, output, original_container_ids,
                  source_snapshot, image_ids):
    """Factory is operator code, never a model URL/image/command. Cleanup must verify."""
    output = Path(output)
    if output.exists():
        raise FileExistsError("Replay requires a fresh output directory")
    output.mkdir(parents=True)
    verdicts, generations = [], []
    seen = set(original_container_ids)
    error = None
    try:
        if claim.spec_id != spec.id:
            raise ValueError("Claim does not select this operator contract")
        for ordinal in range(2):
            with generation_factory(ordinal) as generation:
                profile, config, roles = generation.profile, generation.configuration, generation.role_headers
                container_ids = {x["container_id"] for x in config["services"].values()}
                if not container_ids or seen & container_ids:
                    raise ValueError("Replay reused the research/prior target generation")
                if any(config["services"][name]["image_id"] != expected for name, expected in image_ids.items()):
                    raise ValueError("Replay target image changed")
                seen.update(container_ids)
                actions = [{"tool": "target_http", "service": spec.service, "endpoint": path,
                            "parameters": {"path": path, **({"role_handle": role} if role else {})},
                            "purpose": "Independent confidential-marker control/probe",
                            "expected_evidence": "HTTP observation bound to fresh target generation"}
                           for path, role in [(spec.owner_path, spec.owner_role), (spec.negative_path, None),
                                              (spec.probe_path, None), (spec.owner_path, spec.owner_role)]]
                directory = output / f"trial-{ordinal}"
                rows = execute_plan(profile=profile, configuration=config, actions=actions,
                                    output=directory, role_headers=roles)
                replay_scope = ResearchScope.model_validate(json.loads((directory / "runtime/scope.json").read_text()))
                if replay_scope.source_snapshot != source_snapshot:
                    raise ValueError("Replay source snapshot differs from research")
                observed = audit_observations(directory, rows)
                verdicts.append(marker_trial(observed, spec))
                # Keep only hashes/markers' presence in public summary, not marker value.
                generations.append({"container_ids": sorted(container_ids), "verdict": verdicts[-1],
                                    "observations_sha256": sha256(json.dumps(observed, sort_keys=True).encode()).hexdigest()})
            if not generation.cleanup_verified:
                raise ValueError("Independent target cleanup unverified")
    except (ValueError, KeyError, OSError, RuntimeError):
        error = "Independent replay/control/scope/cleanup failed"
    status = verdicts[0] if error is None and len(verdicts) == 2 and len(set(verdicts)) == 1 else "review_pending"
    summary = {"protocol": "confidential_marker.v1", "spec_id": spec.id, "status": status,
               "scope": "anonymous disclosure of operator-owned confidential marker",
               "generations": generations, "http_requests_expected": 8, "error": error,
               "no_model_script_or_model_success_predicate": True}
    (output / "review.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
