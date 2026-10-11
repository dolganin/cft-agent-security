"""A03 evaluator truth discovery and validation; never imported by production."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

import yaml

from evaluation.benchmark_protocol import ROOT, load_protocol, split_group
from executor.sandbox_audit import calculate_sha256_digest
from fix_verification.workspace import safe_file
from schemas.benchmark_controls import ControlCatalog

DIRECTORY = ROOT / "benchmarks/juice-shop-v20.2.0-v2/controls"
TARGET = ROOT / "artifacts/benchmark-target/juice-shop"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def pinned_files(target: Path) -> list[str]:
    protocol = load_protocol()
    commit = subprocess.check_output(["git", "-C", str(target), "rev-parse", "HEAD"], text=True).strip()
    if commit != protocol.target_commit:
        raise ValueError("Target commit mismatch")
    if subprocess.check_output(["git", "-C", str(target), "status", "--porcelain"]):
        raise ValueError("Target must be clean")
    records = subprocess.check_output(["git", "-C", str(target), "ls-tree", "-rz", "HEAD"]).decode("utf-8")
    files = []
    for record in records.rstrip("\0").split("\0"):
        metadata, file = record.split("\t", 1)
        mode, kind, blob = metadata.split()
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError("Nonregular target entry")
        raw = safe_file(target, file).read_bytes()
        if hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != blob:
            raise ValueError("Source bytes mismatch")
        files.append(file)
    return sorted(files)


def anchor(target: Path, file: str, start: int, end: int) -> dict:
    raw = safe_file(target, file).read_bytes()
    lines = raw.decode().splitlines()
    if not 1 <= start <= end <= len(lines):
        raise ValueError("Invalid anchor")
    return {"file": file, "start": start, "end": end, "sha256": sha(raw),
                "region_sha256": sha(("\n".join(lines[start - 1:end]) + "\n").encode())}


def discover(target: Path) -> dict:
    protocol = load_protocol()
    files = pinned_files(target)
    challenges_file = "data/static/challenges.yml"
    challenges = yaml.safe_load((target / challenges_file).read_text(encoding="utf-8"))
    metadata = {item["key"]: item for item in challenges}
    spans = {}
    for file in files:
        if not (file == "server.ts" or file.startswith(("routes/", "lib/", "models/", "frontend/src/", "infrastructure/", "data/"))):
            continue
        if "/codefixes/" in file or Path(file).suffix not in {".ts", ".js", ".sol", ".yml"}:
            continue
        try:
            lines = (target / file).read_text(encoding="utf-8").splitlines()
        except UnicodeError:
            continue
        starts = {}
        for number, line in enumerate(lines, 1):
            match = re.search(r"vuln-code-snippet (start|end) (.+)", line)
            if match:
                for key in match[2].split():
                    if match[1] == "start":
                        starts[key] = number
                    elif key in starts:
                        spans.setdefault(key, []).append(anchor(target, file, starts.pop(key), number))
    candidates = []
    for file in files:
        match = re.fullmatch(r"data/static/codefixes/(.+)_(\d+)_correct\.(.+)", file)
        if not match:
            continue
        key, variant, _suffix = match.groups()
        info = f"data/static/codefixes/{key}.info.yml"
        details = yaml.safe_load((target / info).read_text(encoding="utf-8")) if info in files else {}
        explanation = next((x["explanation"] for x in details.get("fixes", []) if str(x["id"]) == variant), None)
        candidates.append({"id": f"JS-PATCH-CAND-{key}-{variant}", "control_type": "patched_safe",
            "challenge_key": key, "family": metadata.get(key, {}).get("category", "unmapped"),
            "correct_file": file, "correct_sha256": sha((target / file).read_bytes()),
            "metadata_file": info if info in files else None,
            "metadata_sha256": sha((target / info).read_bytes()) if info in files else None,
            "explanation": explanation, "source_anchors": spans.get(key, []),
            "review_status": "pending", "truth_validated": False,
            "reason": "cannot_prove_safe" if spans.get(key) and explanation else "source_mismatch"})
        slug = re.sub(r"(?<!^)(?=[A-Z])", "-", key.removesuffix("Challenge")).lower()
        known = {"redirectChallenge":"redirect-substring-allowlist",
                 "unionSqlInjectionChallenge":"search-query-sql-interpolation",
                 "dbSchemaChallenge":"search-query-sql-interpolation"}
        cause = known.get(key, "annotation-" + slug)
        candidates[-1].update(root_cause_key=cause, independence_group="juice-" + cause,
            split=split_group("juice-" + cause, protocol.split),
            reconciliation_required=key not in known,
            agent_verifiable_now=False, runtime_eligibility="unverified_candidate")
        if "LIKE '%:criteria%'" in (target / file).read_text(encoding="utf-8"):
            candidates[-1]["reason"] = "correct_fix_not_applicable"
    return {"schema_version": "a03.control_candidates.v1", "target_commit": protocol.target_commit,
        "challenge_metadata_sha256": sha((target / challenges_file).read_bytes()), "candidates": candidates}


def write_yaml(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, allow_unicode=True, sort_keys=False), encoding="utf-8", newline="\n")


def runtime_safe(evidence: dict, *, role_dependent: bool = False) -> bool:
    required = ["build", "tests", "start", "smoke", "reachable", "legitimate_request",
                "property_assertion", "fresh_state", "cleanup", "original_unchanged", "snapshot_removed"]
    if role_dependent:
        required += ["owner_identity", "other_identity", "owned_object", "ownership", "sessions_after"]
    return all(evidence.get(key) is True for key in required)


def validate(target: Path, directory: Path = DIRECTORY) -> dict:
    pinned_files(target)
    generated = yaml.safe_load((directory / "candidates.generated.yaml").read_text(encoding="utf-8"))
    if generated != discover(target):
        raise ValueError("Discovery drift")
    catalog = ControlCatalog.model_validate(yaml.safe_load((directory / "controls.reviewed.yaml").read_text(encoding="utf-8"))).model_dump()
    if catalog["target_commit"] != load_protocol().target_commit:
        raise ValueError("Catalog target mismatch")
    reset = yaml.safe_load((directory / "reset.yaml").read_text(encoding="utf-8"))
    if reset["id"] != "juice-fresh-stage1-v1":
        raise ValueError("Missing reset contract")
    seen, groups = set(), set()
    for control in catalog["controls"]:
        if control["id"] in seen or control["independence_group"] in groups:
            raise ValueError("Duplicate control/group")
        seen.add(control["id"])
        groups.add(control["independence_group"])
        if control["control_type"] not in {"original_safe", "patched_safe", "synthetic_safe"}:
            raise ValueError("Invalid type")
        if not re.fullmatch(r"juice-[a-z0-9-]+", control["independence_group"]):
            raise ValueError("Invalid independence group")
        if control["split"] != split_group(control["independence_group"], load_protocol().split):
            raise ValueError("Split mismatch")
        if not control["family"] or not control["security_property"] or not control["provenance"]:
            raise ValueError("Missing property/provenance")
        for item in control["source_anchors"]:
            if item != anchor(target, item["file"], item["start"], item["end"]):
                raise ValueError("Anchor mismatch")
        if control["reset_contract"] != reset["id"] or not control["availability_checks"]:
            raise ValueError("Missing reset/availability")
        if control["control_type"] == "patched_safe":
            patch = safe_file(directory, control["patch_reference"]).read_bytes()
            if sha(patch) != control["patch_sha256"]:
                raise ValueError("Patch mismatch")
        if control["validation_basis"] == "runtime":
            evidence_path = safe_file(ROOT, control["evidence_reference"])
            raw = evidence_path.read_bytes()
            if sha(raw) != control["evidence_sha256"]:
                raise ValueError("Evidence mismatch")
            runs = json.loads(raw)["cycles"]
            report = json.loads(raw)
            if report["target_commit"] != catalog["target_commit"] or report["bootstrap_sha256"] != sha((ROOT / "evaluation/control_bootstrap.cjs").read_bytes()):
                raise ValueError("Runtime/source fixture binding mismatch")
            if len({x.get("baseline") for x in runs}) != 1 or not all(x.get("baseline") for x in runs):
                raise ValueError("Fresh state drift")
            if len({x["container"] for x in runs}) != len(runs) or not all(x["snapshot_removed"] for x in runs):
                raise ValueError("Reset runtime reused or not cleaned")
            for run in runs:
                audit_raw = safe_file(evidence_path.parent, run["audit_file"]).read_bytes()
                if sha(audit_raw) != run["audit_sha256"]:
                    raise ValueError("Audit mismatch")
                events = [json.loads(line) for line in audit_raw.splitlines()]
                if set(run["stages"]) != {"prepare", "build", "tests", "start", "smoke"}:
                    raise ValueError("Missing stage proof")
                for stage in run["stages"].values():
                    record_raw = safe_file(evidence_path.parent, stage["record_file"]).read_bytes()
                    if sha(record_raw) != stage["record_sha256"]:
                        raise ValueError("Stage record mismatch")
                    record = json.loads(record_raw)
                    matching = [event for event in events if event["evidence_ref"] == stage["execution_ref"]]
                    if len(matching) != 1:
                        raise ValueError("Missing exact audit binding")
                    event = matching[0]
                    payload = {k:v for k,v in record.items() if k not in {"id", "type", "created_at"}}
                    if (event["evidence_digest"] != calculate_sha256_digest(payload)
                            or event["proposal_digest"] != record["action_digest"]
                            or event["action_id"] != record["action_id"]
                            or record["tool"] != "fix_target_stage" or record["status"] != "completed"
                            or record["exit_code"] != 0 or stage["passed"] is not True
                            or event["runtime_backend"] != "docker"):
                        raise ValueError("Stage proof invalid")
            if control["control_type"] == "patched_safe" and (
                    report["patch"]["patch_sha256"] != control["patch_sha256"]
                    or report["patch"]["source_sha256"] != control["source_sha256"]
                    or control["source_sha256"] != control["source_anchors"][0]["sha256"]):
                raise ValueError("Patch/runtime binding mismatch")
            if len(runs) < 2 or not all(runtime_safe(run["properties"][control["property_key"]],
                    role_dependent=bool(control["required_identities"])) for run in runs):
                raise ValueError("Runtime property not validated")
        else:
            from evaluation.control_source import orm_proof
            raw = safe_file(ROOT, control["evidence_reference"]).read_bytes()
            if control["property_key"] != "address_orm" or sha(raw) != control["evidence_sha256"] or json.loads(raw) != orm_proof(target):
                raise ValueError("Reviewed source proof mismatch")
        if control["truth_validated"] is not True or control["agent_verifiable_now"] is not False:
            raise ValueError("Invalid eligibility")
    excluded = yaml.safe_load((directory / "excluded.yaml").read_text(encoding="utf-8"))
    if {x["id"] for x in excluded["controls"]} != {x["id"] for x in generated["candidates"]}:
        raise ValueError("Missing candidate disposition")
    return {"reviewed": len(seen), "independent": len(groups), "candidates": len(generated["candidates"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["discover", "validate"])
    parser.add_argument("--target", type=Path, default=TARGET)
    args = parser.parse_args()
    if args.command == "discover":
        result = discover(args.target)
        write_yaml(DIRECTORY / "candidates.generated.yaml", result)
        write_yaml(DIRECTORY / "excluded.yaml", {"schema_version": "a03.excluded.v1", "controls": [
            {"id": c["id"], "reason": c["reason"], "disposition": "pending",
                 "detail": "Official answer is provenance only; no applied patch/build/availability/property proof"}
            for c in result["candidates"]]})
        print(f"Discovered {len(result['candidates'])} official fix candidates; none automatically safe")
    else:
        print(json.dumps(validate(args.target), sort_keys=True))


if __name__ == "__main__":
    main()
