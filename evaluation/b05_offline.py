"""Verify sealed B05 artifacts and deterministically recompute access verdicts."""
import argparse
import json
from hashlib import sha256
from pathlib import Path

from evidence.access_control import BASKET_WRITE_V3_SCHEDULE, evaluate_access_check
from executor.approvals import proposal_digest
from schemas.access_verification import AccessCheckTrace
from schemas.action import ActionProposal


def verify_artifacts(directory: str | Path) -> dict:
    root = Path(directory).resolve(strict=True)
    seal_path = root / "seal.json"
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    expected = {
        path.relative_to(root).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*")) if path.is_file() and path != seal_path
    }
    if seal != expected:
        raise ValueError("B05 artifact seal does not match the saved files")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    schema_version = manifest.get("schema_version")
    checks = manifest.get("checks", [])
    expected_count = 2 if schema_version == "b05.acceptance.v1" else 1
    if (schema_version not in {"b05.acceptance.v1", "b05.acceptance.v2"}
            or manifest.get("status") not in {"passed", "incomplete"}
            or len(checks) != expected_count):
        raise ValueError("B05 acceptance manifest is incomplete")
    results = []
    for check in checks:
        check_dir = root / check["check_id"]
        if check.get("status") == "unsupported":
            validator = json.loads((check_dir / "validator.json").read_text(encoding="utf-8"))
            if (validator.get("approved") is not False or not check.get("deny_reason")
                    or check.get("cleanup_complete") is not True):
                raise ValueError("Unsupported B05 check lacks a persisted Validator denial")
            results.append({"check_id": check["check_id"], "status": "unsupported",
                            "cleanup_complete": True})
            continue
        if check.get("status") != "passed" or check.get("cleanup_complete") is not True:
            raise ValueError("B05 check did not complete with verified cleanup")
        action = ActionProposal.model_validate_json((check_dir / "action.json").read_text(encoding="utf-8"))
        trace = AccessCheckTrace.model_validate_json((check_dir / "trace.json").read_text(encoding="utf-8"))
        evidence = json.loads((check_dir / "evidence.json").read_text(encoding="utf-8"))
        if (proposal_digest(action) != check.get("action_digest")
                or trace.check_id != check["check_id"]
                or trace.binding_id != check.get("binding_id")
                or trace.source_snapshot_digest != check.get("source_snapshot_digest")
                or trace.exchange_count != check.get("request_count")):
            raise ValueError("B05 action, B01 binding or trace provenance mismatch")
        decision = evaluate_access_check(trace, action)
        if trace.check_id == "juice-basket-own-write-v3":
            _verify_v3_lifecycle(check_dir, trace)
        facts = evidence.get("observation", {}).get("facts", {})
        saved_trace = facts.get("b05_trace")
        saved_decision = facts.get("b05_evidence")
        if (saved_trace != trace.model_dump(mode="json", exclude_unset=True)
                or saved_decision != decision.model_dump(mode="json")
                or evidence.get("verdict") != decision.verdict
                or evidence.get("action_id") != action.id
                or evidence.get("action", {}).get("tool") != "verify_access_control"):
            raise ValueError("B05 persisted Evidence differs from deterministic offline evaluation")
        results.append({"check_id": check["check_id"], "verdict": decision.verdict,
                        "exchange_count": decision.exchange_count,
                        "cleanup_complete": decision.cleanup_complete})
    return {"status": "verified" if manifest["status"] == "passed" else "verified_with_limitations",
            "files": len(seal), "checks": results}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path)
    args = parser.parse_args()
    result = verify_artifacts(args.artifacts)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _verify_v3_lifecycle(check_dir: Path, trace: AccessCheckTrace) -> None:
    lifecycle = check_dir / "fixture-lifecycle"
    log = lifecycle / "lifecycle.jsonl"
    if not log.is_file():
        raise ValueError("B05 v3 lifecycle audit is missing")
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
    profiles = {}
    for path in lifecycle.glob("*/profile.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        generation = data.get("generation")
        if (not isinstance(generation, str) or data.get("active_check_id") != trace.check_id
                or data.get("profile", {}).get("b05_basket_write_v3_candidate") is not True):
            raise ValueError("B05 v3 fixture profile does not match the registered check")
        profile = data["profile"]
        permissions = {(item.get("role_id"), item.get("object_id")): item
                       for item in profile.get("permissions", [])}
        if not (permissions.get(("role-a", "basket-b"), {}).get("update") is False
                and permissions.get(("role-b", "basket-b"), {}).get("update") is True):
            raise ValueError("B05 v3 permission oracle does not prove owner-only update")
        if _digest(generation) in profiles:
            raise ValueError("B05 v3 fixture generation is duplicated")
        profiles[_digest(generation)] = (generation, _digest(profile))
    if set(profiles) != {item.generation_sha256 for item in trace.generations}:
        raise ValueError("B05 v3 profiles do not cover the three persisted generations")
    expected_ops = [
        ("b05-basket-write-v3-first", BASKET_WRITE_V3_SCHEDULE[:8]),
        ("b05-basket-write-v3-second", BASKET_WRITE_V3_SCHEDULE[8:11]),
        ("b05-basket-write-v3-cleanup", BASKET_WRITE_V3_SCHEDULE[11:]),
    ]
    for index, (operation, exchange_ids) in enumerate(expected_ops):
        generation = trace.generations[index]
        raw_generation, profile_digest = profiles[generation.generation_sha256]
        if generation.permission_profile_sha256 != profile_digest:
            raise ValueError("B05 v3 generation does not bind its persisted permission profile")
        candidates = [item for item in records if item.get("generation") == raw_generation
                      and item.get("phase") == operation]
        if len(candidates) != 1 or not isinstance(candidates[0].get("step"), dict):
            raise ValueError("B05 v3 worker operation is absent or duplicated in lifecycle audit")
        step = candidates[0]["step"]
        if (step.get("operation") != operation
                or step.get("generation_sha256") != generation.generation_sha256
                or step.get("role_a_session_binding_sha256") != generation.role_a_session_binding_sha256
                or step.get("role_b_session_binding_sha256") != generation.role_b_session_binding_sha256
                or [item.get("exchange_id") for item in step.get("exchanges", [])] != exchange_ids):
            raise ValueError("B05 v3 lifecycle step differs from trace identity or schedule")
        saved_exchanges = {item.get("exchange_id"): item for item in step.get("exchanges", [])}
        trace_exchanges = {item.exchange_id: item.model_dump(mode="json", exclude_unset=True)
                           for item in trace.exchanges if item.exchange_id in exchange_ids}
        for exchange_id in exchange_ids:
            saved = dict(saved_exchanges[exchange_id])
            expected = dict(trace_exchanges[exchange_id])
            # Runtime combines fixed fragments into one contiguous trace; worker-local indices reset.
            saved.pop("index", None)
            expected.pop("index", None)
            if saved != expected:
                raise ValueError("B05 v3 worker exchange differs from sealed trace")
        saved_snapshots = step.get("basket_snapshots", [])
        expected_snapshots = [item.model_dump(mode="json", exclude_unset=True)
                              for item in trace.basket_snapshots
                              if item.generation_sha256 == generation.generation_sha256]
        if saved_snapshots != expected_snapshots:
            raise ValueError("B05 v3 worker snapshots differ from sealed trace")

if __name__ == "__main__":
    raise SystemExit(main())
