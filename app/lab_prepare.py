"""Operator provisioning of separate pinned Juice Shop clones; never a model tool.

No target scripts execute on the host. Docker provisioning, when explicitly
requested, is separate from verification and its measured artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from app.stage1_e2e import COMMIT, ROOT, digest_pinned_worker_image, pinned_image
from security.error_redaction import redact_error_message

SOURCE = "https://github.com/juice-shop/juice-shop.git"
RUNTIME = "bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b"
COMPOSE_NAME = "docker-compose.presentation.yml"


def command(argv: list[str], *, timeout: int = 180) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False, check=False)
    if result.returncode:
        raise RuntimeError(redact_error_message(result.stderr, max_length=2000))
    return result.stdout.strip()


def clone_target(source: str, destination: Path, *, compose: Path) -> dict:
    """Clone tracked LF bytes; add a local operator Compose exclusion, not .gitignore."""
    if destination.exists():
        raise FileExistsError("Refusing to overwrite target: " + str(destination))
    command(["git", "-c", "core.autocrlf=false", "clone", "--no-local", "--depth", "1",
             "--branch", "v20.2.0", "--", source, str(destination)])
    commit = command(["git", "-C", str(destination), "rev-parse", "HEAD"])
    if commit != COMMIT:
        raise ValueError("Target commit mismatch; partial clone retained for diagnosis")
    # Only this exact operator file is excluded; other untracked files still fail preflight.
    info = destination / ".git" / "info"
    info.mkdir(exist_ok=True)
    exclude = info / "exclude"
    existing = exclude.read_text(encoding="utf-8") if exclude.exists() else ""
    exclude.write_text(existing + f"\n/{COMPOSE_NAME}\n", encoding="utf-8")
    data = compose.read_bytes()
    (destination / COMPOSE_NAME).write_bytes(data)
    status = command(["git", "-C", str(destination), "status", "--porcelain", "--untracked-files=all"])
    if status:
        raise ValueError("Prepared target is not clean")
    source_hash = hashlib.sha256((destination / "routes/search.ts").read_bytes()).hexdigest()
    return {"path": str(destination), "commit": commit, "git_status": status,
            "compose_sha256": hashlib.sha256(data).hexdigest(), "search_source_sha256": source_hash}


def prepare(output: Path, *, source: str = SOURCE, provision_images: bool = False) -> dict:
    output = output.resolve()
    artifacts = (ROOT / "artifacts").resolve()
    if output == artifacts or not output.is_relative_to(artifacts):
        raise ValueError("Use a fresh child directory under this project's artifacts/")
    output.mkdir(parents=True, exist_ok=False)
    manifest_path = output / "preparation.json"
    manifest = {"schema": "cft.lab_preparation.v1", "status": "PREPARING",
                "started_at": datetime.now(UTC).isoformat(), "target_commit": COMMIT,
                "provision_images": provision_images, "targets": {}}

    def save() -> None:
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    save()
    try:
        for purpose in ("analysis", "fix"):
            manifest["targets"][purpose] = clone_target(
                source, output / purpose / "juice-shop", compose=ROOT / "docs/demo/compose.yaml")
            save()
        if provision_images:
            command(["docker", "pull", RUNTIME], timeout=600)
            command(["docker", "pull", "python:3.12-alpine"], timeout=600)
            command(["docker", "build", "--pull", "-f", str(ROOT / "docs/demo/fix-verification.Dockerfile"),
                     "-t", "cft-fix-juice:stage1", str(output / "fix/juice-shop")], timeout=1800)
        manifest["images"] = {
            "worker": digest_pinned_worker_image("python:3.12-alpine"),
            "fix": pinned_image("cft-fix-juice:stage1"),
            "target": pinned_image(RUNTIME),
        }
        manifest["status"] = "READY"
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        manifest["status"] = "FAILED"
        manifest["error"] = redact_error_message(str(exc), max_length=2000)
        raise
    finally:
        manifest["finished_at"] = datetime.now(UTC).isoformat()
        save()
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/operator-lab-v20.2.0")
    parser.add_argument("--source", default=SOURCE, help="Operator Git source; local cache allowed")
    parser.add_argument("--provision-images", action="store_true", help="Explicit Docker network provisioning")
    args = parser.parse_args()
    try:
        manifest = prepare(args.output, source=args.source, provision_images=args.provision_images)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print("Lab preparation failed: " + redact_error_message(str(exc), max_length=2000))
        return 2
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
