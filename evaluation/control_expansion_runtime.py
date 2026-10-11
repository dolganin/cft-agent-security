"""A03.1 evaluator orchestration using unchanged Stage 1 Docker/stage/patch machinery."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from difflib import unified_diff
from pathlib import Path
from uuid import uuid4

from app.stage1_e2e import pinned_image
from evaluation.benchmark_protocol import ROOT, load_protocol
from evaluation.control_catalog import DIRECTORY, TARGET, anchor, pinned_files, sha
from evaluation.control_patch import redirect_patch
from evaluation.control_reset import absent
from evaluation.control_workspace import patched_snapshot
from evidence.audit import JsonlAuditLog
from evidence.store import JsonExecutionEvidenceStore
from executor.approvals import InMemoryApprovalStore
from executor.executor import SafeExecutor
from executor.fix_runtime import DockerFixRuntime
from fix_verification.review import validate_review_diff
from fix_verification.service import FixVerificationService
from fix_verification.workspace import snapshot, tree_digest
from schemas.action import ActionProposal
from schemas.fix import ProposedPatch
from schemas.target import TargetFixConfig, TargetProfile
from validator.validator import PolicyValidator

EXPANSION = DIRECTORY / "expansion"
TESTS = [
    {"file":"test/server/insecurity.unit.test.ts", "start":258, "end":260,
     "name":"returns true for URLs containing allowed URLs", "classification":"vulnerable_behavior_expectation",
     "reason":"Asserts true for an allowlist URL with unapproved appended path; contradicts exact-match property"},
    {"file":"test/server/redirect.unit.test.ts", "start":77, "end":85,
     "name":'tricking the allowlist should solve "redirectChallenge"', "classification":"vulnerable_behavior_expectation",
     "reason":"Asserts challenge solved by off-domain URL containing allowlisted URL; directly asserts the old vulnerability"},
]


def classify_tests(stdout: str, exit_code: int, candidate: str) -> dict:
    match = re.search(r'TEST SUMMARY (\{[^\r\n]*\})', stdout)
    if not match:
        return {"accepted":False, "classification":"unknown", "exceptions":[]}
    summary = json.loads(match[1])
    counts = summary["counts"]
    if (exit_code == 0 and counts["tests"]==415 and counts["passed"]==413
            and counts["skipped"]==2 and counts["failed"] == 0 and counts["cancelled"] == 0):
        return {"accepted":True, "classification":"all_required_tests_passed", "exceptions":[], "summary":summary}
    # Only this candidate, these exact two leaf tests, complete noncancelled suite.
    leaves = re.findall(r'FAIL ([^:]*): AssertionError', stdout)
    expected = [item["name"] for item in TESTS]
    accepted = (candidate == "redirect" and exit_code == 1 and counts["tests"] == 415
        and counts["failed"] == 2 and counts["passed"] == 411 and counts["skipped"] == 2
        and counts["cancelled"] == 0 and sorted(leaves) == sorted(expected)
        and stdout.count("AssertionError") == 2 and "timed out" not in stdout.lower())
    return {"accepted":accepted, "classification":"vulnerable_behavior_expectation_only" if accepted else "functional_regression_or_unknown",
            "exceptions":TESTS if accepted else [], "summary":summary}


def make_patch(target: Path, candidate: str):
    if candidate == "redirect":
        return redirect_patch(target)
    file = "routes/updateProductReviews.ts"
    source = (target / file).read_text(encoding="utf-8")
    old = "    db.reviewsCollection.update( // vuln-code-snippet neutral-line forgedReviewChallenge"
    guard = "    if (typeof req.body.id !== 'string') {\n      res.status(400).send()\n      return\n    }\n"
    after = source.replace(old, guard + old).replace("{ $set: { message: req.body.message } },\n      { multi: true } // vuln-code-snippet vuln-line noSqlReviewsChallenge", "{ $set: { message: req.body.message } }")
    correct_file = "data/static/codefixes/noSqlReviewsChallenge_3_correct.ts"
    correct = (target / correct_file).read_text(encoding="utf-8")
    lines = [line.split("// vuln-code-snippet",1)[0].rstrip() for line in after.splitlines()
             if "vuln-code-snippet hide-line" not in line]
    clean = "\n".join(lines)
    clean = clean[clean.index("export function updateProductReviews"):].strip()
    if re.sub(r"\s+", "", clean) != re.sub(r"\s+", "", correct):
        raise ValueError("Official NoSQL/source correspondence mismatch")
    diff = "".join(unified_diff(source.splitlines(True),after.splitlines(True),fromfile="a/"+file,tofile="b/"+file,n=3))
    validate_review_diff(ProposedPatch(finding_id="A03.1-NoSQL",rationale="Exact official type guard and removal of multi option",unified_diff=diff),
        file=file,source=source,editable_start=14,editable_end=30)
    return {"file":file,"diff":diff,"source_sha256":sha((target/file).read_bytes()),"patch_sha256":sha(diff.encode()),
            "correct_file":correct_file,"correct_sha256":sha((target/correct_file).read_bytes())}


def run_candidate(target: Path, candidate: str):
    pinned_files(target)
    before = snapshot(target)
    patch = make_patch(target,candidate)
    output = EXPANSION / "evidence" / candidate
    output.mkdir(parents=True,exist_ok=True)
    previous=output/"report.json"
    if previous.exists():
        history=output/"history"
        history.mkdir(exist_ok=True)
        (history/("attempt-"+uuid4().hex+".json")).write_bytes(previous.read_bytes())
    patch_file = EXPANSION / "patches" / (candidate+".patch")
    patch_file.parent.mkdir(parents=True,exist_ok=True)
    patch_file.write_text(patch["diff"],encoding="utf-8",newline="\n")
    profile = TargetProfile.from_yaml(ROOT/"targets/juice-presentation.yaml",repository_path_override=target)
    profile = profile.model_copy(update={"fix_verification":TargetFixConfig(image=pinned_image("cft-fix-juice:stage1"),
        service="juice",source_commit=load_protocol().target_commit)})
    script_file = ROOT / "evaluation/control_expansion_oracle.cjs"
    script = script_file.read_text(encoding="utf-8")
    report = {"target_commit":load_protocol().target_commit,"candidate":candidate,"patch":{k:v for k,v in patch.items() if k!="diff"},
              "original_tree_sha256":tree_digest(before),"oracle_sha256":sha(script_file.read_bytes()),
              "image":profile.fix_verification.image,"cycles":[]}
    if candidate == "redirect":
        report["test_provenance"] = [dict(item,anchor=anchor(target,item["file"],item["start"],item["end"])) for item in TESTS]
    for number in (1,2):
        cycle = {"stages":{},"oracle":False,"cleanup":False,"original_unchanged":False}
        runtime = None
        with patched_snapshot(target,patch["file"],patch["diff"],patch["source_sha256"],patch["patch_sha256"]) as source:
            runtime = DockerFixRuntime(profile.model_copy(update={"repository_path":source}))
            cycle["container"] = runtime.id
            stage_dir = output/f"cycle-{number}"
            store = JsonExecutionEvidenceStore(stage_dir/"evidence")
            audit = JsonlAuditLog(stage_dir/"audit.jsonl")
            approvals = InMemoryApprovalStore()
            policy = ROOT/"policies/default.yaml"
            executor = SafeExecutor.from_config(approvals=approvals,policy_file=policy,target_profile=runtime.profile,
                evidence_directory=store.directory,audit_log_path=audit.path,workspace_directory=stage_dir/"workspaces",backend_override="docker")
            validator = PolicyValidator.from_yaml(policy,target_profile=runtime.profile)
            try:
                runtime.open()
                executor.bind_fix_runtime(runtime)
                for stage in ("prepare","build","tests","start","smoke"):
                    action = ActionProposal(id="a031-"+uuid4().hex+"-"+stage,tool="fix_target_stage",target=profile.id,
                        environment=profile.environment,parameters={"adapter":"juice_node_v1","stage":stage},
                        purpose="A03.1 operator fixture stage",expected_evidence="Persisted stage result")
                    execution,_ = FixVerificationService._execute(action,executor,approvals,validator,store,audit)
                    passed = execution.status=="completed" and execution.exit_code==0 and not execution.timed_out
                    classification = classify_tests(execution.stdout,execution.exit_code,candidate) if stage=="tests" else None
                    if classification:
                        passed = classification["accepted"] and not execution.timed_out
                    record = store.directory/(execution.evidence_ref+".json")
                    raw = record.read_bytes().replace(b"\r\n",b"\n")
                    record.write_bytes(raw)
                    cycle["stages"][stage]={"accepted":passed,"exit_code":execution.exit_code,"record":record.relative_to(ROOT).as_posix(),
                        "sha256":sha(raw),"classification":classification}
                    if not passed:
                        raise ValueError("Required stage rejected: "+stage)
                result = runtime._control(["docker","exec","--workdir","/workspace/target",runtime.id,"node","-e",
                    "process.env.CFT_A031_CASE="+json.dumps(candidate)+";\n"+script],timeout=60)
                if result.exit_code!=0 or result.timed_out:
                    raise ValueError("Independent oracle/availability failed")
                body=json.loads(result.stdout)
                cycle.update(oracle=True,oracle_result=body)
            except (OSError,ValueError,RuntimeError,TimeoutError):
                cycle["failure"]="No safe verdict: stage or independent oracle failed"
            finally:
                cycle["cleanup"] = runtime.close() and absent("container",runtime.id) and absent("network",runtime.network)
                cycle["original_unchanged"] = snapshot(target)==before
                raw = audit.path.read_bytes().replace(b"\r\n",b"\n") if audit.path.exists() else b""
                audit.path.write_bytes(raw)
                cycle.update(audit=audit.path.relative_to(ROOT).as_posix(),audit_sha256=sha(raw))
        cycle["snapshot_removed"] = not source.exists()
        report["cycles"].append(cycle)
        (output/"report.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8",newline="\n")
        print(f"A03.1 {candidate} cycle {number}: oracle={cycle['oracle']}, cleanup={cycle['cleanup']}",flush=True)
    return report


def run_synthetic():
    source=EXPANSION/"synthetic"
    image=pinned_image("python:3.12-alpine")
    report={"fixture_sha256":sha((source/"fixtures.py").read_bytes()),"oracle_sha256":sha((source/"tests/check_fixture.py").read_bytes()),"image":image,"cycles":[]}
    for _ in range(2):
        name="cft-a031-synthetic-"+uuid4().hex[:16]
        cycle={"container":name,"passed":False,"assertions":{},"cleanup":False}
        try:
            result=subprocess.run(["docker","run","--name",name,"--pull","never","--network","none","--read-only",
            "--cap-drop","ALL","--security-opt","no-new-privileges","--pids-limit","16","--memory","64m","--cpus","1",
            "--user","1000:1000","--mount",f"type=bind,source={source.resolve()},target=/fixture,readonly",
            "--entrypoint","python",image,"-B","/fixture/tests/check_fixture.py"],capture_output=True,text=True,timeout=30,check=False)
            cycle.update(passed=result.returncode==0,assertions=json.loads(result.stdout) if result.returncode==0 else {})
        finally:
            removed=subprocess.run(["docker","rm","--force",name],capture_output=True,text=True,timeout=15,check=False)
            cycle["cleanup"]=removed.returncode==0 and absent("container",name)
        report["cycles"].append(cycle)
    output=EXPANSION/"evidence/synthetic.json"
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("A03.1 synthetic fixture checks recorded",flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate",choices=["redirect","nosql","synthetic"])
    parser.add_argument("--target",type=Path,default=TARGET)
    args=parser.parse_args()
    if args.candidate=="synthetic":
        run_synthetic()
    else:
        run_candidate(args.target,args.candidate)
