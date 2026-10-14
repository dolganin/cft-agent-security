"""Recompute B06 verdicts from a sealed archive without Docker or LLM calls."""
import argparse
import json
from hashlib import sha256
from pathlib import Path

from evidence.interpreter import build_evidence
from schemas.action import ActionProposal
from schemas.b06_verification import B06_TOOLS
from schemas.execution import ExecutionResult
from security.source_paths import normalize_source_path


def replay(directory):
    directory = Path(directory).resolve(strict=True)
    seal = json.loads((directory / "seal.json").read_text())
    if any(p.is_symlink() for p in directory.rglob("*")):
        raise ValueError("B06 replay cannot follow symlinks")
    actual = {p.relative_to(directory).as_posix(): sha256(p.read_bytes()).hexdigest()
              for p in directory.rglob("*") if p.is_file() and p.name != "seal.json"}
    if actual != seal:
        raise ValueError("B06 sealed package is incomplete or changed")
    manifest = json.loads((directory / "acceptance.json").read_text())
    if manifest.get("status") != "passed" or len(manifest.get("checks", [])) != 4:
        raise ValueError("B06 requires a complete original/safe acceptance package")
    expected_cases = {(tool, variant) for tool in B06_TOOLS for variant in ("original", "safe")}
    if {(c.get("tool"), c.get("variant")) for c in manifest["checks"]} != expected_cases:
        raise ValueError("B06 acceptance membership must contain the four fixed cases")
    checks = []
    for check in manifest["checks"]:
        name = check["tool"] + ("-safe" if check["variant"] == "safe" else "-original")
        root = directory / name
        action = ActionProposal.model_validate_json((root / "action.json").read_text())
        if (action.tool != check["tool"] or action.verification_binding is None
                or check["expected"] != ("rejected" if check["variant"] == "safe" else "confirmed")):
            raise ValueError("B06 action or expected outcome differs from the fixed case")
        hashes = {}
        for relative in action.verification_binding.source_files:
            name = normalize_source_path(relative)
            hashes[name] = sha256((root / "source" / name).read_bytes()).hexdigest()
        if hashes != action.verification_binding.source_files:
            raise ValueError("B06 source snapshots do not match the archived binding")
        records = list((root / "execution").glob("*.json"))
        if len(records) != 1:
            raise ValueError("Each B06 acceptance action needs exactly one persisted execution")
        record = json.loads(records[0].read_text())
        execution = ExecutionResult(run_id=record["run_id"], action_id=record["action_id"],
            status=record["status"], exit_code=record["exit_code"], timed_out=record["timed_out"],
            evidence_ref=record["id"], audit_ref=record["audit_ref"],
            artifacts=[str(records[0]), str(root / "audit.jsonl")])
        evidence = build_evidence(action=action, execution=execution, record=record,
            evidence_loaded=True, artifact_refs=execution.artifacts, hypothesis_id=action.id,
            sandbox_session_id=record["session_id"])
        checks.append({"tool": action.tool, "variant": check["variant"], "expected": check["expected"],
                       "observed": evidence.verdict, "consistent": evidence.verdict == check["expected"]})
    return {"schema_version": "cft.b06.offline_replay.v1", "status": "passed" if all(c["consistent"] for c in checks) else "failed",
            "checks": checks, "code_support": manifest["code_support"]["status"], "docker_or_llm_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(args.input.resolve()):
        raise ValueError("Replay output must not change the sealed inputs")
    result = replay(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
