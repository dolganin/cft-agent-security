"""B04 operator acceptance: two independent disposable generations, no LLM."""
import argparse
import json
from hashlib import sha256
from pathlib import Path

from executor.access_fixture import ROOT, AccessFixtureLab


def run(repository, output):
    lab = AccessFixtureLab(repository, output)
    result = {"status": "failed", "fixture_id": lab.fixture_id, "cycles": [],
              "scope": "B04 identity/ownership/availability, not B05 vulnerability verification"}
    try:
        with lab:
            previous = None
            baselines = None
            for cycle in range(2):
                context = lab.prepare() if cycle == 0 else lab.reset()
                if context.status != "ready":
                    raise ValueError(context.reason)
                if previous is not None and lab.controls(previous).status != "inconclusive":
                    raise ValueError("Old fixture handle was not invalidated")
                current = {o.id: o.baseline_sha256 for o in context.objects}
                if baselines is not None and current != baselines:
                    raise ValueError("Logical fixture data differs after independent reset")
                baselines = current
                checks = {}
                for diagnostic in ["control", "lost-session", "changed-identity", "control"]:
                    observed = lab.controls(context, diagnostic=diagnostic)
                    expected = "ready" if diagnostic == "control" else "inconclusive"
                    if observed.status != expected:
                        raise ValueError("Unexpected fixture control status")
                    checks[diagnostic] = observed.status
                result["cycles"].append({"generation": context.generation,
                                          "context": context.model_dump(mode="json"), "checks": checks})
                previous = context
        if lab.controls(previous).status != "inconclusive":
            raise ValueError("Closed fixture handle remained usable")
        if not all(r["cleanup_complete"] and r["original_unchanged"]
                   for r in lab.records if r["phase"] == "destroy"):
            raise ValueError("Cleanup/source integrity not verified")
        result.update(status="passed", cleanup_complete=True, original_unchanged=True,
                      repeatable_baselines=True, stale_handles_blocked=True)
    except (OSError, ValueError, RuntimeError):
        result["reason"] = "fixture_acceptance_failed; inspect lifecycle.jsonl"
        lab.close()
    finally:
        output = Path(output)
        inputs = ["schemas/access_fixture.py", "schemas/target.py", "executor/access_fixture.py",
                  "executor/access_fixture_worker.py", "app/access_fixture_acceptance.py",
                  "targets/juice-access-fixture.yaml"]
        result["implementation_sha256_lf"] = {name: sha256(
            (ROOT / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest() for name in inputs}
        (output / "acceptance.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        seal = {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
                for p in output.rglob("*") if p.is_file()}
        (output / "seal.json").write_text(json.dumps(seal, indent=2) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path("artifacts/benchmark-target/juice-shop"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = run(args.repository, args.output)
    print(json.dumps({"status": result["status"], "cycles": len(result["cycles"]),
                      "cleanup_complete": result.get("cleanup_complete", False)}, indent=2))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
