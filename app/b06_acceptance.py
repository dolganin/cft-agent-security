"""Real B06 Docker acceptance through canonical Validator/Executor/Evidence."""
import argparse
import json
from hashlib import sha256
from pathlib import Path

from agent.verification import register_source_artifacts, verification_candidates
from evidence.audit import JsonlAuditLog
from evidence.interpreter import build_evidence
from evidence.store import JsonExecutionEvidenceStore
from executor.access_fixture import ROOT, WORKER_IMAGE
from executor.approvals import InMemoryApprovalStore
from executor.b06_runtime import B06Runtime
from executor.executor import SafeExecutor
from executor.sandbox import DockerSandbox, RunLimiter
from executor.sandbox_policy import SandboxLimits, SandboxPolicy
from executor.targets import TargetRegistry
from sast.identity import normalize_finding
from schemas.action import ActionProposal
from schemas.finding import Finding
from schemas.target import TargetProfile
from validator.validator import PolicyValidator


def write(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run(output):
    output = Path(output).resolve()
    if output.exists() or not output.is_relative_to(ROOT / "artifacts") or output == ROOT / "artifacts":
        raise ValueError("Use a new child directory under artifacts/")
    output.mkdir(parents=True)
    manifest = {"schema_version": "cft.b06.acceptance.v1", "status": "failed", "checks": []}
    findings = []
    try:
        template = TargetProfile.from_yaml(ROOT / "targets/juice-b06-verification.yaml")
        for tool, file, marker, family in (
            ("verify_redirect_destination", "lib/insecurity.ts", "allowed = allowed ||", "open-redirect"),
            ("verify_auth_reauthentication", "routes/changePassword.ts", "if (currentPassword &&", "authentication"),
        ):
            line = next(i for i, text in enumerate((template.repository_path / file).read_text().splitlines(), 1)
                        if marker in text)
            finding = normalize_finding(Finding(id=tool, source="operator_acceptance", rule_id=family,
                title=tool, description="Fixed operator B06 runtime acceptance, no discovery metric",
                file=file, line_start=line, line_end=line), repository_root=template.repository_path)
            profile = register_source_artifacts(template, [finding], template.repository_path)
            findings.append(finding.model_dump(mode="json"))
            write(output / "operator-findings.json", findings)
            for safe in (False, True):
                name = tool + ("-safe" if safe else "-original")
                runtime = B06Runtime(profile, tool, output / name, safe_control=safe)
                try:
                    runtime.open()
                    if "code_support" not in manifest:
                        manifest["code_support"] = runtime.code_support()
                        if manifest["code_support"]["status"] != "unsupported_runtime":
                            raise ValueError("Code evaluation requires a separate supported runtime protocol")
                    mapped_finding = finding.model_copy(update={"provenance": None}) if safe else finding
                    candidate, = verification_candidates({"target_profile": runtime.profile,
                        "finding": mapped_finding, "runtime_services": runtime.runtime_map()})
                    action = ActionProposal(id=name, tool=tool, target=profile.id, environment="sandbox",
                        parameters=candidate["parameters"], purpose="Verify the operator B06 claim",
                        expected_evidence="Independent controls, readback and cleanup",
                        service=candidate["service"], endpoint=candidate["endpoint"],
                        verification_binding=candidate["verification_binding"], fixture_binding=candidate["fixture_binding"])
                    validator = PolicyValidator.from_yaml(ROOT / "policies/b06.yaml", target_profile=runtime.profile)
                    validator.fixture_bindings[profile.id] = runtime.binding
                    validation = validator.validate(action)
                    if not validation.approved:
                        raise ValueError(validation.reason)
                    approvals = InMemoryApprovalStore()
                    approvals.record(action, validation)
                    policy = SandboxPolicy(backend="docker", sandbox_image=WORKER_IMAGE,
                        limits=SandboxLimits(wall_time_seconds=60, cpu_time_seconds=3, max_output_bytes=65536))
                    store = JsonExecutionEvidenceStore(output / name / "execution")
                    audit = JsonlAuditLog(output / name / "audit.jsonl")
                    executor = SafeExecutor(approvals=approvals, targets=TargetRegistry([runtime.profile]),
                        evidence_store=store, audit_log=audit, sandbox=DockerSandbox(policy),
                        run_limiter=RunLimiter(1, 1), policy=policy)
                    executor.bind_verification_runtime(runtime)
                    execution = executor.execute_sequence([action], runtime_services=runtime.runtime_map()).results[0].execution
                    record = store.get_execution(execution.evidence_ref)
                    evidence = build_evidence(action=action, execution=execution, record=record,
                        evidence_loaded=True, artifact_refs=execution.artifacts, hypothesis_id=name,
                        sandbox_session_id=runtime.id)
                    write(output / name / "action.json", action.model_dump(mode="json"))
                    write(output / name / "validation.json", validation.model_dump(mode="json"))
                    write(output / name / "evidence.json", evidence.model_dump(mode="json"))
                    expected = "rejected" if safe else "confirmed"
                    check = {"tool": tool, "variant": "safe" if safe else "original",
                             "expected": expected, "observed": evidence.verdict,
                             "execution_status": execution.status, "cleanup_complete": runtime.close(),
                             "audit_records": len(audit.records())}
                    manifest["checks"].append(check)
                    write(output / "acceptance.json", manifest)
                    if evidence.verdict != expected or execution.status != "completed" or not check["cleanup_complete"]:
                        raise ValueError("B06 acceptance verdict mismatch: " + name)
                finally:
                    runtime.close()
        code_file = "routes/userProfile.ts"
        code_line = next(i for i, text in enumerate((template.repository_path / code_file).read_text().splitlines(), 1)
                         if "username = eval(code)" in text)
        code_finding = normalize_finding(Finding(id="operator-code-evaluation", source="operator_acceptance",
            rule_id="code-injection", title="Code evaluation runtime support",
            description="Operator availability check, not a detection benchmark",
            file=code_file, line_start=code_line, line_end=code_line), repository_root=template.repository_path)
        findings.append(code_finding.model_dump(mode="json"))
        write(output / "operator-findings.json", findings)
        manifest["status"] = "passed"
    except (OSError, ValueError, RuntimeError) as exc:
        manifest["error"] = str(exc)
    finally:
        implementation = [p for base in ("app", "agent", "schemas", "executor", "evidence", "validator", "security")
                          for p in (ROOT / base).glob("*.py")]
        manifest["implementation_sha256"] = {p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()).hexdigest()
                                             for p in sorted(implementation)}
        manifest["operator_inputs_sha256"] = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in (
            "policies/b06.yaml", "targets/juice-b06-verification.yaml", "targets/juice-access-fixture.yaml",
            "docs/b06-verification-specification.md")}
        write(output / "acceptance.json", manifest)
        write(output / "seal.json", {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
                                    for p in output.rglob("*") if p.is_file() and p.name != "seal.json"})
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.output)
    print(json.dumps({"status": result["status"], "checks": result["checks"], "error": result.get("error")}, indent=2))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
