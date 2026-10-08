"""Operator CLI for evidence-backed isolated fix verification."""
import argparse
from pathlib import Path

from fix_verification.service import FixVerificationService
from schemas.fix import PatchReviewArtifact
from schemas.report import FinalReport
from schemas.target import TargetProfile


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a reviewed patch in disposable Docker targets")
    parser.add_argument("--report", required=True)
    parser.add_argument("--review", required=True)
    parser.add_argument("--profile", required=True, help="Operator-owned TargetProfile YAML")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    artifact = FixVerificationService().verify(
        report=FinalReport.model_validate_json(Path(args.report).read_text(encoding="utf-8")),
        review=PatchReviewArtifact.model_validate_json(Path(args.review).read_text(encoding="utf-8")),
        profile=TargetProfile.from_yaml(args.profile), artifact_directory=output.parent,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(artifact.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(f"{artifact.status}: security_verified={artifact.security_verified}")
    return 0 if artifact.security_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
