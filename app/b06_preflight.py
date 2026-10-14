"""Read-only static preflight for the pinned B06 Juice Shop claims.

This command checks the frozen checkout and relevant source/config anchors. It does
not start Docker, send requests, execute target code, or produce vulnerability
verdicts.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import yaml

from evaluation.scanner_baseline import validate_target
from executor.access_fixture import COMMIT, ROOT, TARGET_IMAGE

TARGET = ROOT / "artifacts/benchmark-target/juice-shop"
SPEC = ROOT / "docs/b06-verification-specification.md"
SOURCE_FILES = (
    "server.ts",
    "routes/changePassword.ts",
    "routes/redirect.ts",
    "lib/insecurity.ts",
    "routes/updateUserProfile.ts",
    "routes/userProfile.ts",
    "data/static/challenges.yml",
    "config/default.yml",
    "lib/utils.ts",
)


def _sha256(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def _read_text(files: dict[str, str], name: str) -> str:
    path = TARGET / name
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(TARGET.resolve()) or path.is_symlink():
        raise ValueError("B06 source path is not canonical: " + name)
    raw = path.read_bytes()
    raw.decode("utf-8")
    files[name] = _sha256(raw)
    return raw.decode("utf-8")


def _require(source: str, snippets: tuple[str, ...], label: str) -> None:
    missing = [snippet for snippet in snippets if snippet not in source]
    if missing:
        raise ValueError("Pinned source no longer matches B06 anchor: " + label)


def _challenge(challenges: object, key: str) -> dict:
    if not isinstance(challenges, list):
        raise TypeError("Unsupported Juice Shop challenges.yml structure")
    matches = [item for item in challenges if isinstance(item, dict) and item.get("key") == key]
    if len(matches) != 1:
        raise ValueError("Expected one challenge metadata record: " + key)
    return matches[0]


def build_report() -> dict[str, object]:
    """Build source-only supportability facts; runtime support remains unverified."""
    tracked_files = validate_target(TARGET, SimpleNamespace(target_commit=COMMIT))
    sources: dict[str, str] = {}
    text = {name: _read_text(sources, name) for name in SOURCE_FILES}

    _require(text["server.ts"], (
        "app.get('/rest/user/change-password', utils.asyncHandler(changePassword()))",
        "app.get('/redirect', performRedirect())",
        "app.get('/profile', utils.asyncHandler(getUserProfile()))",
        "app.post('/profile', utils.asyncHandler(updateUserProfile()))",
    ), "route registration")
    _require(text["routes/changePassword.ts"], (
        "if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password)",
        "await user.update({ password: newPasswordInString })",
    ), "password change handler")
    _require(text["routes/redirect.ts"], (
        "if (security.isRedirectAllowed(toUrl))",
        "res.redirect(toUrl)",
    ), "redirect handler")
    _require(text["lib/insecurity.ts"], (
        "allowed = allowed || url.includes(allowedUrl)",
    ), "redirect allowlist helper")
    _require(text["routes/userProfile.ts"], (
        "if (utils.isChallengeEnabled(challenges.usernameXssChallenge))",
        "username = eval(code)",
    ), "username evaluation branch")
    _require(text["routes/updateUserProfile.ts"], (
        "const savedUser = await user.update({ username: req.body.username })",
        "res.redirect(process.env.BASE_PATH + '/profile')",
    ), "username update path")

    challenge_records = yaml.safe_load(text["data/static/challenges.yml"])
    code_challenge = _challenge(challenge_records, "usernameXssChallenge")
    default_config = yaml.safe_load(text["config/default.yml"])
    if not isinstance(default_config, dict):
        raise TypeError("Unsupported Juice Shop default config structure")
    challenges_config = default_config.get("challenges")
    if not isinstance(challenges_config, dict):
        raise TypeError("Missing Juice Shop default challenge config")
    safety_mode = challenges_config.get("safetyMode")
    disabled_env = code_challenge.get("disabledEnv", [])
    docker_disabled = isinstance(disabled_env, list) and "Docker" in disabled_env

    source_hash = _sha256(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode())
    tracked_hash = _sha256(json.dumps(tracked_files, sort_keys=True, separators=(",", ":")).encode())
    code_status = (
        "runtime_gate_required"
        if docker_disabled and safety_mode == "auto"
        else "runtime_gate_required_unexpected_config"
    )
    code_gate_reason = (
        "challenge declares Docker disabled and default safety mode is auto; runtime image/config still needs observation"
        if docker_disabled and safety_mode == "auto"
        else "challenge or default safety mode differs from the expected pinned configuration; runtime probe remains blocked"
    )

    return {
        "schema_version": "cft.b06.preflight.v1",
        "status": "static_preflight_complete",
        "generated_at": datetime.now(UTC).isoformat(),
        "measurement_performed": False,
        "target": {
            "profile_id": "juice-b06-verification",
            "repository": "artifacts/benchmark-target/juice-shop",
            "commit": COMMIT,
            "target_image": TARGET_IMAGE,
            "tracked_tree_sha256": tracked_hash,
            "b06_source_snapshot_sha256": source_hash,
            "source_files": sources,
            "specification_sha256": _sha256(SPEC.read_bytes()),
        },
        "claims": {
            "JS-AUTH-001": {
                "source_status": "candidate_condition_present",
                "runtime_status": "not_run",
                "claim": "Authenticated user can change own password without supplying the current password.",
                "scope_limit": "Does not establish unauthenticated access or access to another account.",
            },
            "JS-REDIRECT-001": {
                "source_status": "candidate_condition_present",
                "runtime_status": "not_run",
                "claim": "The redirect handler returns the supplied destination after a substring allowlist check.",
                "scope_limit": "Requires later header-only controls and probe; this preflight performs no HTTP request.",
            },
            "JS-CODE-001": {
                "source_status": "evaluation_branch_present",
                "runtime_gate": code_status,
                "runtime_status": "not_run",
                "safety_mode_default": safety_mode,
                "disabled_in_environment": docker_disabled,
                "runtime_gate_reason": code_gate_reason,
                "claim": "Runtime availability must be established before any code-evaluation probe.",
            },
        },
        "limitations": [
            "Source anchors and the pinned Git tree were checked; the target image was not inspected or started.",
            "No HTTP exchanges, active probes, security verdicts, or benchmark metrics were produced.",
            "Auth and redirect runtime claims require B06 controls and Docker acceptance.",
        ],
    }


def write_report(report: dict[str, object], output: Path) -> None:
    artifacts_root = (ROOT / "artifacts").resolve()
    destination = output.expanduser().resolve()
    if destination == artifacts_root or not destination.is_relative_to(artifacts_root):
        raise ValueError("B06 preflight output must be a new directory under artifacts/")
    if destination.exists():
        raise FileExistsError("Refusing to overwrite an existing B06 output directory")
    destination.mkdir(parents=True)
    report_path = destination / "preflight.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    seal = {"preflight.json": _sha256(report_path.read_bytes())}
    (destination / "seal.json").write_text(json.dumps(seal, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = build_report()
        write_report(report, args.output)
    except (OSError, TypeError, ValueError, RuntimeError, subprocess.SubprocessError, yaml.YAMLError) as exc:
        print("B06 preflight failed: " + str(exc))
        return 2
    print(json.dumps({
        "status": report["status"],
        "measurement_performed": False,
        "claims": {
            key: value.get("runtime_gate", value["runtime_status"])
            for key, value in report["claims"].items()
        },
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
