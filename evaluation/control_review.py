"""Publish four explicitly scoped, reviewed controls only after real fixture proof."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from evaluation.benchmark_protocol import ROOT, load_protocol, split_group
from evaluation.control_catalog import (
    DIRECTORY,
    TARGET,
    anchor,
    runtime_safe,
    sha,
    validate,
    write_yaml,
)
from evaluation.control_patch import redirect_patch
from evaluation.control_source import orm_proof


def publish_evidence(source: Path, name: str) -> tuple[str, str]:
    report = json.loads((source / "reset-evidence.json").read_text(encoding="utf-8"))
    destination = DIRECTORY / "evidence" / name
    destination.mkdir(parents=True, exist_ok=True)
    for number, cycle in enumerate(report["cycles"], 1):
        stage_source = source / f"cycle-{number}"
        for stage, result in cycle["stages"].items():
            file = stage_source / "evidence" / (result["execution_ref"] + ".json")
            relative = f"cycle-{number}/{stage}.json"
            copy = destination / relative
            copy.parent.mkdir(parents=True, exist_ok=True)
            copy.write_bytes(file.read_bytes().replace(b"\r\n", b"\n"))
            result.update(record_file=relative, record_sha256=sha(copy.read_bytes()))
        events = (stage_source / "audit.jsonl").read_bytes().replace(b"\r\n", b"\n")
        file = destination / f"cycle-{number}/audit.jsonl"
        file.write_bytes(events)
        cycle.update(audit_file=f"cycle-{number}/audit.jsonl", audit_sha256=sha(events))
    raw = (json.dumps(report, indent=2) + "\n").encode()
    file = destination / "reset-evidence.json"
    file.write_bytes(raw)
    return file.relative_to(ROOT).as_posix(), sha(raw)


def publish(target: Path = TARGET):
    originals = ROOT / "artifacts/a03-checks/original"
    patched = ROOT / "artifacts/a03-checks/patched"
    reports = [json.loads((originals / "reset-evidence.json").read_text(encoding="utf-8"))]
    for report, keys in zip(reports, [("address_owner","card_owner","card_mask")], strict=True):
        if len(report["cycles"]) != 2:
            raise ValueError("Incomplete real reset proof")
        for cycle in report["cycles"]:
            for key in keys:
                if not runtime_safe(cycle["properties"].get(key, {}), role_dependent=key.endswith("owner")):
                    raise ValueError("Cannot publish safe control without all preconditions")
    references = [publish_evidence(originals, "original")]
    publish_evidence(patched, "redirect-rejected")
    patch = redirect_patch(target)
    patch_path = DIRECTORY / "patches/redirect-exact.patch"
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_text(patch["diff"], encoding="utf-8", newline="\n")
    # These are scoped manual decisions, not guessed from filenames/scanner silence.
    specs = [
        ("JS-SAFE-AUTHZ-001", "authorization", "address-read-owner-scope", "address_owner", "routes/address.ts", 16, 25,
         "/api/Addresss/{id}", "An authenticated user cannot read another fixture user's address by ID; own address remains accessible."),
        ("JS-SAFE-AUTHZ-002", "authorization", "card-read-owner-scope", "card_owner", "routes/payment.ts", 43, 69,
         "/api/Cards/{id}", "An authenticated user cannot read another fixture user's payment method by ID; own card remains accessible."),
        ("JS-SAFE-DATA-001", "sensitive_data", "card-number-response-mask", "card_mask", "routes/payment.ts", 20, 68,
         "/api/Cards and /api/Cards/{id}", "Fixture card number is masked in owner list and item GET responses, exposing only the last four digits."),
    ]
    controls = []
    for id_, family, key, prop, file, start, end, endpoint, property_ in specs:
        is_patch = family == "redirect"
        reference, evidence_sha = references[int(is_patch)]
        roles = ["owner", "other_user"] if family == "authorization" else []
        control = {"id": id_, "family": family, "control_type": "patched_safe" if is_patch else "original_safe",
            "root_cause_key": key, "independence_group": "juice-" + key,
            "split": split_group("juice-" + key, load_protocol().split), "security_property": property_,
            "source_anchors": [anchor(target, file, start, end)], "http_anchors": [endpoint], "service": "juice",
            "required_identities": roles, "required_test_data": ["owner and other_user fixture objects" if roles else "fixed legitimate fixture request"],
            "availability_checks": ["build/tests/start/smoke passed", "legitimate request succeeds before and after assertion",
                "server identity and owned object verified" if roles else "successful expected response, no timeout"],
            "safe_expected_behaviour": property_, "failure_meaning": "Any missing precondition is unavailable/inconclusive, never safe",
            "provenance": ["Pinned upstream source plus manual property review", "Two actual disposable Docker fixture cycles"],
            "reset_contract": "juice-fresh-stage1-v1", "cleanup_requirements": ["container absent", "network absent", "snapshot removed", "original byte-identical"],
            "review_status": "reviewed", "validation_basis": "runtime", "truth_validated": True, "agent_verifiable_now": False,
            "runtime_eligibility": "evaluator_fixture_only", "property_key": prop, "evidence_reference": reference, "evidence_sha256": evidence_sha}
        if roles:
            control["source_anchors"].extend([anchor(target, "server.ts", 457 if prop == "card_owner" else 467,
                461 if prop == "card_owner" else 471), anchor(target, "lib/insecurity.ts", 175, 184)])
        if is_patch:
            control.update(patch_reference="patches/redirect-exact.patch", patch_sha256=patch["patch_sha256"],
                source_sha256=patch["source_sha256"])
            control["source_anchors"].append(anchor(target, "routes/redirect.ts", 12, 30))
            control["provenance"].extend([patch["correct_file"], "data/static/codefixes/redirectChallenge.info.yml"])
        controls.append(control)
    proof = orm_proof(target)
    proof_file = DIRECTORY / "evidence/address-orm-source.json"
    proof_file.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8", newline="\n")
    source_control = dict(controls[0])
    source_control.update(id="JS-SAFE-SQL-001", family="sql_injection", root_cause_key="address-id-orm-lookup",
        independence_group="juice-address-id-orm-lookup", property_key="address_orm",
        split=split_group("juice-address-id-orm-lookup", load_protocol().split),
        security_property="In the reviewed address item lookup, route id is a Sequelize where value rather than interpolated SQL statement text.",
        source_anchors=[proof["anchor"],anchor(target, "models/address.ts", 7, 16)],
        required_identities=[], required_test_data=["exact pinned source expression and Sequelize model provenance"],
        availability_checks=["not applicable to source-only property; no runtime SQL verdict"],
        safe_expected_behaviour="Source construction uses ORM where object; does not establish safety of other queries/endpoints",
        provenance=["Manual review of exact getAddressById expression and ORM model import"],
        validation_basis="source_review", runtime_eligibility="truth_only",
        evidence_reference=proof_file.relative_to(ROOT).as_posix(), evidence_sha256=sha(proof_file.read_bytes()))
    controls.append(source_control)
    write_yaml(DIRECTORY / "controls.reviewed.yaml", {"schema_version": "a03.controls.v1",
        "target_commit": load_protocol().target_commit, "controls": controls})
    exclusions = []
    generated = yaml.safe_load((DIRECTORY / "candidates.generated.yaml").read_text(encoding="utf-8"))
    for candidate in generated["candidates"]:
        attempted = candidate["correct_file"] == patch["correct_file"]
        exclusions.append({"id": candidate["id"], "reason": "build_failure" if attempted else candidate["reason"],
            "disposition": "excluded" if attempted else "pending",
            "detail": "Patch applies and builds, but upstream tests intentionally require vulnerable substring redirects: 2 failures, no safe verdict" if attempted else
                "No complete applied patch/build/availability/property proof; official answer alone is insufficient"})
        if attempted:
            evidence = DIRECTORY / "evidence/redirect-rejected/reset-evidence.json"
            exclusions[-1].update(patch_reference="patches/redirect-exact.patch", patch_sha256=patch["patch_sha256"],
                source_sha256=patch["source_sha256"], evidence_reference=evidence.relative_to(ROOT).as_posix(),
                evidence_sha256=sha(evidence.read_bytes()), original_unchanged=True, cleanup_complete=True)
    write_yaml(DIRECTORY / "excluded.yaml", {"schema_version": "a03.excluded.v1", "controls": exclusions})
    print(json.dumps(validate(target), sort_keys=True))


if __name__ == "__main__":
    publish()
