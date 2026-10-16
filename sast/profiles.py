"""Small, digest-locked Semgrep profile loader for reproducible scans."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SUPPORTED_EXCLUDES = [".venv", "node_modules", "dist", "build"]


def _parse_index_records(raw: bytes) -> list[tuple[str, str, str, str]]:
    """Parse Git's NUL-delimited index records without locale decoding paths."""
    if not raw or not raw.endswith(b"\0"):
        raise ValueError("Target Git index output is malformed")

    records = []
    for record in raw[:-1].split(b"\0"):
        metadata, separator, path_bytes = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3 or not path_bytes:
            raise ValueError("Target Git index record is malformed")
        try:
            mode, blob, stage = (field.decode("ascii", errors="strict") for field in fields)
            relative = path_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("Target Git index contains invalid UTF-8 path data") from exc
        records.append((mode, blob, stage, relative))
    return records


def load_scan_profile(path: str | Path) -> dict:
    profile_path = Path(path).expanduser().resolve()
    value = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != "cft.semgrep-profile.v1":
        raise ValueError("Not a supported CFT Semgrep profile")
    required = {"schema", "id", "version", "semgrep_version", "target_commit",
                "config_files", "config_sha256", "exclude", "signal_types"}
    if set(value) != required:
        raise ValueError("Semgrep profile fields do not match the supported schema")
    if (value["id"] != "juice-shop-v2" or value["version"] != 1
            or value["semgrep_version"] != "1.174.0"
            or not re.fullmatch(r"[0-9a-f]{40}", str(value["target_commit"]))):
        raise ValueError("Semgrep profile identity or version pin is invalid")
    if value["exclude"] != SUPPORTED_EXCLUDES:
        raise ValueError("Semgrep profile exclusions differ from runner behavior")
    if value["signal_types"] != {
        "code": "implemented", "configuration": "unsupported_by_local_ruleset",
        "dependency": "unsupported_no_sca",
    }:
        raise ValueError("Semgrep profile signal coverage is not explicit")
    lock_path = profile_path.with_name("profile.lock.json")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    expected_profile = hashlib.sha256(profile_path.read_bytes()).hexdigest()
    if (lock.get("schema") != "cft.semgrep-profile-lock.v1"
            or lock.get("profile_sha256") != expected_profile):
        raise ValueError("Semgrep profile lock digest mismatch")
    files = value.get("config_files")
    digests = value.get("config_sha256")
    if not isinstance(files, list) or not files or not isinstance(digests, dict):
        raise ValueError("Semgrep profile requires config_files and config_sha256")
    resolved = []
    for relative in files:
        if not isinstance(relative, str) or Path(relative).is_absolute():
            raise ValueError("Semgrep profile config paths must be relative")
        config = (profile_path.parent / relative).resolve()
        if not config.is_relative_to(ROOT):
            raise ValueError("Semgrep profile config escaped the repository")
        if not config.is_file():
            raise ValueError(f"Semgrep profile config is missing: {relative}")
        actual = hashlib.sha256(config.read_bytes()).hexdigest()
        expected = digests.get(relative)
        if actual != expected:
            raise ValueError(f"Semgrep profile config digest mismatch: {relative}")
        resolved.append(str(config))
    return {
        **value,
        "profile_path": str(profile_path),
        "config_files": resolved,
        "config_sha256": dict(digests),
        "profile_sha256": expected_profile,
        "lock_path": str(lock_path),
    }


def validate_target_snapshot(target: str | Path, expected_commit: str) -> dict:
    """Require a clean checkout and verify every tracked file against Git blobs."""
    target_path = Path(target).expanduser().resolve(strict=True)

    def git(*args: str) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(target_path), *args], capture_output=True,
            check=False, timeout=30,
        )
        if result.returncode:
            try:
                detail = result.stderr.decode("utf-8", errors="strict").strip()[:500]
            except UnicodeDecodeError:
                detail = "Git returned a non-UTF-8 diagnostic"
            raise ValueError(f"Target provenance check failed: {detail}")
        return result.stdout

    try:
        commit = git("rev-parse", "HEAD").decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("Target Git commit id is not ASCII") from exc
    if commit != expected_commit:
        raise ValueError("Target commit differs from Semgrep profile pin")
    if git("status", "--porcelain", "--untracked-files=all", "-z"):
        raise ValueError("Target checkout must be clean, including untracked files")
    file_hashes = {}
    for mode, blob, stage, relative in _parse_index_records(git("ls-files", "-s", "-z")):
        path = target_path / relative
        if stage != "0" or mode not in {"100644", "100755"} or path.is_symlink():
            raise ValueError("Target contains an unsupported tracked file")
        if not path.resolve().is_relative_to(target_path):
            raise ValueError("Target path escaped the pinned checkout")
        content = path.read_bytes()
        actual_blob = hashlib.sha1(
            b"blob " + str(len(content)).encode() + b"\0" + content
        ).hexdigest()
        if actual_blob != blob:
            raise ValueError("Target file bytes differ from the pinned Git tree")
        file_hashes[relative] = hashlib.sha256(content).hexdigest()
    tree_digest = hashlib.sha256(json.dumps(
        sorted(file_hashes.items()), separators=(",", ":")
    ).encode()).hexdigest()
    return {
        "commit": commit, "tracked_files": len(file_hashes),
        "files_sha256": tree_digest,
    }


def classify_diagnostics(raw: dict) -> tuple[list[dict], list[dict]]:
    """Return known partial-coverage warnings and fatal/unclassified diagnostics."""
    errors = raw.get("errors", [])
    if not isinstance(errors, list):
        return [], [{"message": "Semgrep errors field is not a list"}]
    coverage = []
    fatal = []
    recognized = {("Syntax error", 3), ("PartialParsing", 3), ("Timeout", 2)}
    for item in errors:
        kind = item.get("type") if isinstance(item, dict) else None
        if isinstance(kind, list) and kind:
            kind = kind[0]
        if (isinstance(item, dict) and item.get("level") == "warn"
                and (kind, item.get("code")) in recognized):
            coverage.append(item)
        else:
            fatal.append(item if isinstance(item, dict) else {"message": str(item)})
    return coverage, fatal


def classify_signal_type(rule_id: str, path: str, metadata: dict | None = None) -> str:
    explicit = (metadata or {}).get("signal")
    if explicit in {"code", "configuration", "dependency"}:
        return explicit
    normalized = path.replace("\\", "/").lower()
    rule = rule_id.lower()
    if (rule.startswith(("yaml.", "dockerfile.")) or "/.github/workflows/" in normalized
            or normalized.endswith((".yaml", ".yml", "dockerfile"))):
        return "configuration"
    return "code"
