"""Pinned source-only storage-chain acceptance; no target execution or LLM."""
import argparse
import subprocess
from hashlib import sha256
from pathlib import Path

from app.research_juice_smoke import COMMIT
from evidence.password_storage_review import review_password_storage
from reporting.checkpoints import write_json
from sast.profiles import validate_target_snapshot

ROOT = Path(__file__).resolve().parents[1]


def run(checkout, output):
    checkout, output = checkout.resolve(strict=True), output.resolve()
    if output.exists() or output.is_relative_to(checkout) or checkout.is_relative_to(output):
        raise ValueError("Choose a fresh output outside the target checkout")
    snapshot = validate_target_snapshot(checkout, COMMIT)
    names = ("models/user.ts", "lib/insecurity.ts")
    source_sha256 = {name: sha256((checkout / name).read_bytes()).hexdigest() for name in names}
    result = review_password_storage(root=checkout, model_file=names[0], helper_file=names[1],
                                     source_sha256=source_sha256)
    if validate_target_snapshot(checkout, COMMIT) != snapshot:
        raise ValueError("Target changed during source review")
    output.mkdir(parents=True)
    write_json(output / "review.json", result)
    implementation = ("evidence/password_storage_review.py", "evidence/research_source_reviewer.py",
                      "security/verification_binding.py", "app/juice_password_source_review.py")
    write_json(output / "manifest.json", {"schema": "cft.juice.password-source-review.v1",
        "target": snapshot, "source_sha256": source_sha256, "source_unchanged": True,
        "scope": "source_condition_only", "runtime_confirmation_added": False,
        "target_code_executed": False, "model_calls": 0,
        "implementation_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "implementation_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in implementation}})
    write_json(output / "seal.json", {path.name: sha256(path.read_bytes()).hexdigest()
        for path in sorted(output.iterdir()) if path.is_file()})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.checkout, args.output)
    print(result["status"] + ": " + result["reason"])


if __name__ == "__main__":
    main()
