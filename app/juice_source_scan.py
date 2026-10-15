"""Produce source-grounded Juice Shop candidates without model or evaluator input."""
from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from hashlib import sha256
from pathlib import Path

from app.research_juice_smoke import COMMIT
from discovery.service import ProjectDiscovery
from pipeline.juice_source_detectors import detect_juice_source_candidates
from reporting.checkpoints import write_json
from sast.identity import normalize_finding
from sast.profiles import load_scan_profile, validate_target_snapshot
from sast.semgrep_runner import run_semgrep_scan
from schemas.target import TargetProfile
from security.error_redaction import redact_observation
from tools.repository_source import RepositorySource

ROOT = Path(__file__).resolve().parents[1]


def scan(checkout: Path, output: Path, *, with_sast: bool = False) -> dict:
    checkout, output = checkout.resolve(strict=True), output.resolve()
    if output.exists() or output.is_relative_to(checkout):
        raise ValueError("Use a fresh output directory outside the target")
    before = validate_target_snapshot(checkout, COMMIT)
    inventory = ProjectDiscovery().discover(checkout)
    source = RepositorySource(inventory, research_mode=True)
    profile = TargetProfile(id="juice-source-development", environment="sandbox",
        repository_path=checkout, services={"juice": {"internal_port": 3000}})
    findings = [normalize_finding(f, repository_root=checkout,
                                  service_resolver=profile.resolve_service)
                for f in detect_juice_source_candidates(profile, source)]
    output.mkdir(parents=True)
    write_json(output / "source-findings.json", [f.model_dump(mode="json") for f in findings])
    sast_findings = []
    if with_sast:
        rules = load_scan_profile(ROOT / "sast/rules/juice-shop-v2/profile.yaml")
        version = subprocess.check_output(["semgrep", "--version"], text=True,
            stderr=subprocess.STDOUT, timeout=20).strip().splitlines()[-1]
        if version != rules["semgrep_version"]:
            raise ValueError("Semgrep version differs from the pinned scan profile")
        result = run_semgrep_scan(checkout, config=rules["config_files"], timeout_seconds=120)
        sast_findings = result.findings
        write_json(output / "sast/findings.json", [f.model_dump(mode="json") for f in sast_findings])
        write_json(output / "sast/raw-redacted.json", redact_observation(result.raw))
    after = validate_target_snapshot(checkout, COMMIT)
    if before != after:
        raise ValueError("Target changed during source scan")
    manifest = {"schema": "cft.juice.source-scan.v1", "target": before,
        "source_unchanged": True, "source_files": list(source.files),
        "source_sha256": {p: sha256((checkout / p).read_bytes()).hexdigest() for p in source.files},
        "detector_findings": len(findings), "sast_observations": len(sast_findings),
        "sast_enabled": with_sast, "source_detector_enabled": True,
        "families": dict(sorted(Counter(f.provenance.family for f in findings).items())),
        "implementation": {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in (
            "pipeline/juice_source_detectors.py", "tools/repository_source.py", "app/juice_source_scan.py",
            "sast/identity.py", "discovery/service.py")},
        "model_calls": 0, "runtime_verification_performed": False,
        "scope": "Source candidates only; no confirmed verdict or runtime coverage claim"}
    write_json(output / "manifest.json", manifest)
    write_json(output / "seal.json", {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
        for p in sorted(output.rglob("*")) if p.is_file()})
    return {k: manifest[k] for k in ("detector_findings", "sast_observations", "families", "source_unchanged")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--with-sast", action="store_true")
    args = parser.parse_args()
    print(json.dumps(scan(args.checkout, args.output, with_sast=args.with_sast), ensure_ascii=False))


if __name__ == "__main__":
    main()
