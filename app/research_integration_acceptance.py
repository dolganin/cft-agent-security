"""R05–R06 acceptance: synthetic model, real canonical graph/Docker and independent review."""
import json
import secrets
import tempfile
import time
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from app.research_acceptance import docker
from app.research_campaign import campaign
from evidence.research_http_replay import replay_marker
from schemas.finding import Finding
from schemas.research import ResearchFile, ResearchScope
from schemas.research_agent import (
    HttpProofClaim,
    ResearchCandidate,
    ResearchChoice,
    ResearchTurn,
    SourceProofClaim,
)
from schemas.research_campaign import CampaignLimits
from schemas.research_review import HttpMarkerSpec
from schemas.target import TargetProfile

ROOT = Path(__file__).resolve().parents[1]


class SourceClient:
    max_output_tokens = 4096

    def complete_model(self, **kwargs):
        observations = kwargs["user_payload"]["observations"]
        if not observations:
            return ResearchTurn(summary="Read the actual code", hypothesis="Inspect a digest call",
                action=ResearchChoice(tool="read_source", parameters={"path": "app.ts"},
                                      purpose="Read code", expected_evidence="Numbered source"))
        ref = observations[-1]["action_id"]
        return ResearchTurn(summary="Independent proof is required", hypothesis="Weak digest call in source", finish=True,
            observation_refs=[ref], source_claims=[SourceProofClaim(protocol="weak_digest_call.v1", file="app.ts",
                line_start=2, line_end=2, observation_refs=[ref])],
            candidates=[ResearchCandidate(rule_id="weak-cryptography.md5", title="MD5 digest call",
                description="Explicit weak digest invocation, runtime impact unknown", file="app.ts", line_start=2,
                line_end=2, provenance_paths=["app.ts"], rationale="Read source before independent review",
                observation_refs=[ref], anchor="crypto.createHash('md5')")])


def run(output, image):
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError("Choose a fresh acceptance output")
    output.mkdir(parents=True)
    checks = {}
    with tempfile.TemporaryDirectory(prefix="cft-r05-r06-fixture-") as temp:
        root = Path(temp)
        source = root / "app.ts"
        source.write_text("import crypto from 'crypto';\ncrypto.createHash('md5');\n")
        profile = TargetProfile(id="research-integration-fixture", repository_path=root, environment="sandbox")
        sast = [Finding(id="sast-md5", source="semgrep", rule_id="weak-hash", title="MD5 digest call",
                        description="Source candidate", file="app.ts", line_start=2, line_end=2)]
        summary = campaign(profile=profile, configuration={"worker_image": image, "source_files": ["app.ts"]},
            client=SourceClient(), output=output / "campaign", sast=sast, limits=CampaignLimits(max_questions=1))
        findings = json.loads((output / "campaign/findings.json").read_text())
        reports = json.loads((output / "campaign/reports.json").read_text())
        checks["scanner-model-dedup-with-origins"] = len(findings) == 1 and len(findings[0]["provenance"]["observations"]) == 2
        checks["independent-source-positive"] = summary["review_counts"]["confirmed"] == 1
        checks["canonical-report-confirmed-source-only"] = reports[0]["report"]["status"] == "confirmed" and "source condition" in reports[0]["report"]["evidence"][-1]["summary"]
        checks["read-coverage-recorded"] = json.loads((output / "campaign/coverage.json").read_text())["read_lines"] == 2

        marker = "owned-marker-" + secrets.token_hex(12)
        spec = HttpMarkerSpec(id="owned-fixture", service="fixture", owner_path="/owner", negative_path="/negative",
                              probe_path="/probe", owner_role="owner", marker=marker)
        expected_source = ResearchScope(target_id=profile.id, session_id="research-" + "a" * 32,
            worker_image=image, worker_sha256="b" * 64,
            source_files={"app.ts": ResearchFile(original_sha256=sha256(source.read_bytes()).hexdigest(),
                                                visible_sha256=sha256(source.read_bytes()).hexdigest())}).source_snapshot
        target_image = json.loads(docker(["image", "inspect", image]))[0]["Id"]

        def factory(mode):
            @contextmanager
            def generation(ordinal):
                prefix = "cft-r06-" + uuid4().hex[:12]
                network, container = prefix + "-net", prefix + "-target"
                token = secrets.token_hex(20)
                docker(["network", "create", "--internal", network])
                context = SimpleNamespace(cleanup_verified=False)
                try:
                    container_id = docker(["run", "--detach", "--pull=never", "--name", container,
                        "--network", network, "--network-alias", "fixture", "--read-only", "--user=65534:65534",
                        "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=8", "--memory=64m",
                        "--env", "OWNER_TOKEN=" + token, "--env", "OWNED_MARKER=" + marker,
                        "--env", "FIXTURE_MODE=" + mode, "--mount",
                        f"type=bind,src={ROOT / 'executor/research_review_fixture.py'},dst=/app/review-fixture.py,readonly",
                        image, "python3", "/app/review-fixture.py"])
                    # Trusted preparation only; no model script/network here.
                    time.sleep(.3)
                    context.profile = profile
                    context.role_headers = {"owner": {"Authorization": "Bearer " + token}}
                    context.configuration = {"worker_image": image, "source_files": ["app.ts"], "network_name": network,
                        "services": {"fixture": {"container_id": container_id, "image_id": target_image,
                            "address": "http://fixture:8080", "read_prefixes": ["/"], "role_handles": ["owner"]}}}
                    yield context
                finally:
                    docker(["rm", "--force", container])
                    docker(["network", "rm", network])
                    context.cleanup_verified = True
            return generation

        for mode, expected in [("disclosed", "confirmed"), ("safe", "rejected")]:
            result = replay_marker(claim=HttpProofClaim(protocol="confidential_marker.v1", spec_id=spec.id,
                observation_refs=["synthetic-http-read"]), spec=spec, generation_factory=factory(mode),
                output=output / ("http-" + mode), original_container_ids=[], source_snapshot=expected_source,
                image_ids={"fixture": target_image})
            checks["independent-http-" + mode] = result["status"] == expected
            checks["fresh-generations-" + mode] = len(result["generations"]) == 2 and len({
                c for g in result["generations"] for c in g["container_ids"]}) == 2
    summary = {"passed": all(checks.values()), "checks": checks,
               "live_llm": False, "benchmark_measurement": False, "reasoning": "synthetic test double"}
    (output / "acceptance.json").write_text(json.dumps(summary, indent=2) + "\n")
    seal = {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest() for p in sorted(output.rglob("*")) if p.is_file()}
    (output / "seal.json").write_text(json.dumps(seal, indent=2) + "\n")
    if not summary["passed"]:
        raise RuntimeError("R05–R06 acceptance failed; outputs retained")
    return summary


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.image), indent=2))
