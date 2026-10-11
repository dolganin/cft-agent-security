"""A03.1 publication, reconciliation and validation. No scorer or production integration."""
from __future__ import annotations

import argparse
import json
from collections import Counter

import yaml

from evaluation.benchmark_protocol import ROOT, load_protocol, split_group
from evaluation.control_catalog import DIRECTORY, TARGET, anchor, pinned_files, sha, write_yaml
from evaluation.control_catalog import validate as validate_a03
from evaluation.control_expansion_runtime import EXPANSION, TESTS, classify_tests, make_patch
from evaluation.control_expansion_sources import SPECS, source_proof
from executor.sandbox_audit import calculate_sha256_digest
from fix_verification.workspace import safe_file
from schemas.benchmark_control_expansion import ExpandedControl

POSITIVES = ROOT/"benchmarks/juice-shop-v20.2.0-v2/catalog/positives.reviewed.yaml"
SYNTHETIC = [
    ("JS-SAFE-XSS-101","xss","JS-XSS-001","html_text","Plain text is HTML-escaped inside a fixed paragraph; controlled script markup cannot form an element."),
    ("JS-SAFE-PATH-102","path-traversal","JS-PATH-001","archive_path","Archive destination normalizes within the fixed approved root and rejects absolute, backslash and escaping names."),
    ("JS-SAFE-XXE-101","xml-external-entities","JS-XXE-001","xml_no_dtd","The small XML fixture rejects DTD/entity declarations before parsing and accepts ordinary XML text."),
    ("JS-SAFE-CODE-101","code-evaluation","JS-CODE-001","profile_literal","Profile names are treated as literal strings; expression-looking input is returned as data without evaluation."),
]


def read_yaml(file):
    return yaml.safe_load(file.read_text(encoding="utf-8"))


def frozen_inputs():
    return read_yaml(EXPANSION/"frozen-inputs.yaml")["sha256"]


def preserve():
    equivalents=read_yaml(EXPANSION/"frozen-inputs.yaml").get("eol_equivalent_sha256",{})
    if set(equivalents)-{"benchmarks/juice-shop-v20.2.0-v2/protocol.lock.json"}:
        raise ValueError("EOL equivalence is allowed only for protocol JSON lock")
    for file,digest in frozen_inputs().items():
        observed=sha(safe_file(ROOT,file).read_bytes())
        if observed!=digest and equivalents.get(file)!=observed:
            raise ValueError("Existing A03/A02 input changed: "+file)
    load_protocol()


def reconcile(controls, positives):
    by_id={p["id"]:p for p in positives}
    rows=[]
    for control in sorted(controls,key=lambda x:x["id"]):
        related=control.get("related_positive_case_ids",[])
        for id_ in related:
            positive=by_id.get(id_)
            if positive is None or (control["independence_group"],control["split"],control["related_root_cause_key"]) != (
                    positive["independence_group"],positive["split"],positive["root_cause_key"]):
                raise ValueError("A02 safe twin group/split/cause mismatch")
        rows.append({"control_id":control["id"],"related_positive_case_ids":related,
            "related_root_cause_key":control.get("related_root_cause_key"),"control_group":control["independence_group"],
            "positive_groups":[by_id[id_]["independence_group"] for id_ in related],
            "split":control["split"],"status":"matched" if related else "independent_safe_property"})
    return rows


def runtime_proof(report, candidate, target=TARGET):
    if report.get("candidate")!=candidate or len(report.get("cycles",[]))!=2:
        raise ValueError("Incomplete runtime proof")
    if report["oracle_sha256"]!=sha((ROOT/"evaluation/control_expansion_oracle.cjs").read_bytes()):
        raise ValueError("Independent oracle changed")
    if candidate=="redirect":
        expected=[dict(item,anchor=anchor(target,item["file"],item["start"],item["end"])) for item in TESTS]
        if report.get("test_provenance")!=expected:
            raise ValueError("Case-specific vulnerable-test source evidence missing")
    seen=set()
    for cycle in report["cycles"]:
        if cycle["container"] in seen or not all(cycle.get(k) is True for k in ["oracle","cleanup","original_unchanged","snapshot_removed"]):
            raise ValueError("Runtime isolation, property or cleanup not proven")
        seen.add(cycle["container"])
        if set(cycle["stages"])!={"prepare","build","tests","start","smoke"}:
            raise ValueError("Incomplete stage proof")
        audit_raw=safe_file(ROOT,cycle["audit"]).read_bytes()
        if sha(audit_raw)!=cycle["audit_sha256"]:
            raise ValueError("Audit mismatch")
        events=[json.loads(line) for line in audit_raw.splitlines()]
        for name,stage in cycle["stages"].items():
            raw=safe_file(ROOT,stage["record"]).read_bytes()
            if sha(raw)!=stage["sha256"] or stage["accepted"] is not True:
                raise ValueError("Stage proof rejected")
            record=json.loads(raw)
            event=[e for e in events if e["evidence_ref"]==record["id"]]
            if (len(event)!=1 or event[0]["evidence_digest"]!=calculate_sha256_digest({k:v for k,v in record.items() if k not in {"id","type","created_at"}})
                    or event[0]["proposal_digest"]!=record["action_digest"] or event[0]["action_id"]!=record["action_id"]
                    or event[0]["runtime_backend"]!="docker" or record["session_id"]!=cycle["container"]
                    or event[0]["session_id"]!=cycle["container"] or not record["action_id"].endswith("-"+name)):
                raise ValueError("Missing persisted stage/audit binding")
            if record["timed_out"] or record["tool"]!="fix_target_stage":
                raise ValueError("Invalid stage execution")
            if name=="tests":
                actual=classify_tests(record["stdout"],record["exit_code"],candidate)
                if actual!=stage["classification"] or not actual["accepted"]:
                    raise ValueError("Unknown/functional test failure")
            elif record["exit_code"]!=0 or record["status"]!="completed":
                raise ValueError("Required functional stage failed")
        result=cycle["oracle_result"]
        if not all(result.get(k) is True for k in ["reachable","legitimate","negative_assertion","post_available"]):
            raise ValueError("Availability/negative assertion failed")
        if candidate=="nosql" and not all(result.get(k) is True for k in ["identity","resource_exists","post_identity"]):
            raise ValueError("Identity/resource precondition failed")


def base_control(id_,kind,family,root,property_,basis,evidence,oracle):
    return {"id":id_,"control_type":kind,"family":family,"root_cause_key":root,"independence_group":"juice-"+root,
        "split":split_group("juice-"+root,load_protocol().split),"security_property":property_,"oracle":oracle,
        "related_positive_case_ids":[],"related_root_cause_key":None,"relation":"independent_safe_property",
        "source_anchors":[],"http_anchors":[],"service":"juice","required_identities":[],"required_test_data":[],
        "availability_checks":["Source-only scoped proof; no runtime verdict"] if basis=="source_review" else ["Legitimate before request", "Negative assertion", "Legitimate/session after request"],
        "reset_contract":"juice-fresh-stage1-v1","cleanup_requirements":["Original unchanged", "Disposable runtime/snapshot absent when used"],
        "provenance":["Pinned source and explicit operator-reviewed oracle"],"validation_basis":basis,"runtime_verdict":None,
        "truth_validated":True,"agent_verifiable_now":False,"review_status":"reviewed",
        "evidence_reference":evidence.relative_to(ROOT).as_posix(),"evidence_sha256":sha(evidence.read_bytes()),
        "limitations":"Scoped evaluator truth only; no production Agent capability or runtime REJECTED inferred"}


def publish(target=TARGET):
    preserve()
    pinned_files(target)
    positives=read_yaml(POSITIVES)["cases"]
    by_id={p["id"]:p for p in positives}
    controls=[]
    for spec in SPECS:
        file=EXPANSION/"evidence"/('source-'+spec["id"]+'.json')
        proof=source_proof(target,spec)
        if json.loads(file.read_text(encoding="utf-8"))!=proof:
            raise ValueError("Original source proof changed")
        control=base_control(spec["id"],"original_safe",spec["family"],spec["root"],spec["property"],"source_review",file,"reviewed_exact_source_branch_v1")
        control.update(source_anchors=[proof["anchor"]],http_anchors=[spec["endpoint"]],limitations=spec["scope"])
        controls.append(control)
    dispositions=[]
    for candidate,id_,family,positive_id,property_ in [
        ("redirect","JS-SAFE-REDIRECT-101","open-redirect","JS-REDIRECT-001","Exact allowlisted redirect succeeds; four unapproved URL variants return no Location while the service remains available."),
        ("nosql","JS-SAFE-NOSQL-101","nosql-injection","JS-NOSQL-001","A literal existing review ID updates one fixture review; operator-object, number and null IDs are denied without changing reviews.")]:
        file=EXPANSION/"evidence"/candidate/"report.json"
        report=json.loads(file.read_text(encoding="utf-8"))
        try:
            runtime_proof(report,candidate)
        except ValueError as exc:
            dispositions.append({"candidate":candidate,"status":"pending","reason":str(exc)})
            continue
        patch=make_patch(target,candidate)
        if report["patch"]!={k:v for k,v in patch.items() if k!="diff"}:
            raise ValueError("Runtime/source patch mismatch")
        positive=by_id[positive_id]
        control=base_control(id_,"patched_safe",family,positive["root_cause_key"],property_,"runtime",file,"fixed_independent_http_fixture_v1")
        control.update(related_positive_case_ids=[positive_id],related_root_cause_key=positive["root_cause_key"],relation="direct_safe_twin",
            source_anchors=[anchor(target,patch["file"],1,len((target/patch["file"]).read_text(encoding="utf-8").splitlines()))],
            http_anchors=["GET /redirect"] if candidate=="redirect" else ["PATCH /rest/products/reviews"],
            required_identities=[] if candidate=="redirect" else ["operator-owned review user"],
            required_test_data=["Exact allowlisted URL"] if candidate=="redirect" else ["Existing operator-owned fixture review"],
            patch_reference=(EXPANSION/"patches"/(candidate+".patch")).relative_to(ROOT).as_posix(),
            patch_sha256=patch["patch_sha256"],source_sha256=patch["source_sha256"],
            provenance=[patch["correct_file"],"Two fresh Stage1 cycles with persisted stages and independent oracle"])
        controls.append(control)
        dispositions.append({"candidate":candidate,"status":"reviewed","control_id":id_,"reason":"All functional stages and independent oracle accepted"})
    file=EXPANSION/"evidence/synthetic.json"
    proof=json.loads(file.read_text(encoding="utf-8"))
    if (proof["fixture_sha256"]!=sha((EXPANSION/"synthetic/fixtures.py").read_bytes())
            or proof["oracle_sha256"]!=sha((EXPANSION/"synthetic/tests/check_fixture.py").read_bytes())
            or len(proof["cycles"])!=2 or not all(x["passed"] and x["cleanup"] for x in proof["cycles"])):
        raise ValueError("Synthetic fixtures not independently verified")
    for id_,family,positive_id,key,property_ in SYNTHETIC:
        if not all(x["assertions"].get(key) is True for x in proof["cycles"]):
            raise ValueError("Missing synthetic property assertions")
        positive=by_id[positive_id]
        control=base_control(id_,"synthetic_safe",family,positive["root_cause_key"],property_,"fixture_behavior",file,key)
        path=(EXPANSION/"synthetic/fixtures.py").relative_to(ROOT).as_posix()
        control.update(related_positive_case_ids=[positive_id],related_root_cause_key=positive["root_cause_key"],relation="direct_safe_twin",
            service="synthetic-fixture",reset_contract="synthetic-fresh-process-v1",
            source_anchors=[anchor(ROOT,path,1,len((ROOT/path).read_text(encoding="utf-8").splitlines()))],
            provenance=["Minimal stdlib synthetic fixture, separate from Juice Shop", "Two networkless fresh Docker processes"],
            limitations="Demonstrates fixture property only, not Juice Shop runtime or full parser/browser behavior")
        controls.append(control)
    parsed=[ExpandedControl.model_validate(c).model_dump() for c in controls]
    original=read_yaml(DIRECTORY/"controls.reviewed.yaml")["controls"]
    rows=reconcile(original+parsed,positives)
    write_yaml(EXPANSION/"controls.reviewed.yaml",{"schema_version":"a03.1.controls.v1","controls":parsed})
    write_yaml(DIRECTORY/"reconciliation.yaml",{"schema_version":"a03.1.reconciliation.v1","positives_sha256":sha(POSITIVES.read_bytes()),"controls":rows})
    generated=read_yaml(DIRECTORY/"candidates.generated.yaml")["candidates"]
    selected={x["candidate_id"]:x for x in read_yaml(EXPANSION/"triage.yaml")["selected_candidates"]}
    all_dispositions=[]
    for c in generated:
        row={"id":c["id"],"previous_disposition":next(x for x in read_yaml(DIRECTORY/"excluded.yaml")["controls"] if x["id"]==c["id"]),
             "status":"pending","reason":"not_selected_after_static_triage"}
        if c["id"] in selected:
            s=selected[c["id"]]
            row.update(status=s["disposition"],reason=s["reason"])
        for decision in dispositions:
            if c["challenge_key"]==("redirectChallenge" if decision["candidate"]=="redirect" else "noSqlReviewsChallenge"):
                row.update(decision)
        all_dispositions.append(row)
    write_yaml(EXPANSION/"dispositions.yaml",{"schema_version":"a03.1.dispositions.v1","candidates":all_dispositions})
    print(json.dumps(validate(target),indent=2))


def validate(target=TARGET):
    preserve()
    validate_a03(target)
    positives=read_yaml(POSITIVES)["cases"]
    controls=[ExpandedControl.model_validate(x).model_dump() for x in read_yaml(EXPANSION/"controls.reviewed.yaml")["controls"]]
    old=read_yaml(DIRECTORY/"controls.reviewed.yaml")["controls"]
    all_controls=old+controls
    if len({x["id"] for x in all_controls})!=len(all_controls):
        raise ValueError("Duplicate control ID")
    if len({(x["independence_group"],x["control_type"]) for x in all_controls})!=len(all_controls):
        raise ValueError("Duplicate independent property in slice")
    rows=reconcile(all_controls,positives)
    reconciliation=read_yaml(DIRECTORY/"reconciliation.yaml")
    if reconciliation["controls"]!=rows or reconciliation["positives_sha256"]!=sha(POSITIVES.read_bytes()):
        raise ValueError("Reconciliation drift")
    for c in controls:
        if c["split"]!=split_group(c["independence_group"],load_protocol().split):
            raise ValueError("Noncanonical split")
        for a in c["source_anchors"]:
            if a!=anchor(ROOT if c["control_type"]=="synthetic_safe" else target,a["file"],a["start"],a["end"]):
                raise ValueError("Source anchor drift")
        raw=safe_file(ROOT,c["evidence_reference"]).read_bytes()
        if sha(raw)!=c["evidence_sha256"]:
            raise ValueError("Property proof drift")
        proof=json.loads(raw)
        if c["control_type"]=="original_safe":
            spec=next(x for x in SPECS if x["id"]==c["id"])
            if proof!=source_proof(target,spec):
                raise ValueError("Source oracle mismatch")
        elif c["control_type"]=="patched_safe":
            patch_raw=safe_file(ROOT,c["patch_reference"]).read_bytes()
            if sha(patch_raw)!=c["patch_sha256"] or proof["patch"]["source_sha256"]!=c["source_sha256"]:
                raise ValueError("Patch binding mismatch")
            runtime_proof(proof,proof["candidate"])
        elif (proof["fixture_sha256"]!=sha((EXPANSION/"synthetic/fixtures.py").read_bytes())
                or proof["oracle_sha256"]!=sha((EXPANSION/"synthetic/tests/check_fixture.py").read_bytes())
                or len(proof["cycles"])!=2
                or not all(x["cleanup"] and x["passed"] and x["assertions"].get(c["oracle"]) is True for x in proof["cycles"])):
            raise ValueError("Synthetic assertion proof failed")
    dispositions=read_yaml(EXPANSION/"dispositions.yaml")["candidates"]
    if {x["id"] for x in dispositions}!={x["id"] for x in read_yaml(DIRECTORY/"candidates.generated.yaml")["candidates"]}:
        raise ValueError("Missing disposition")
    return {"starting":len(old),"added":len(controls),"reviewed_total":len(all_controls),
        "independent_groups":len({x["independence_group"] for x in all_controls}),
        "types":dict(Counter(x["control_type"] for x in all_controls)),
        "split":dict(Counter(x["split"] for x in all_controls)),
        "source_only":sum(x["validation_basis"]=="source_review" for x in all_controls),
        "runtime_validated":sum(x["validation_basis"]=="runtime" for x in all_controls),
        "synthetic_behavior":sum(x["validation_basis"]=="fixture_behavior" for x in all_controls),
        "direct_twins":sum(bool(x.get("related_positive_case_ids")) for x in all_controls)}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=["publish","validate"])
    args=parser.parse_args()
    if args.command=="publish":
        publish()
    else:
        print(json.dumps(validate(),indent=2))
