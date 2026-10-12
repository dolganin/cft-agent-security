"""A06 isolated scanner orchestration. No Agent, Validator or Gate changes."""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import subprocess
import tarfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import yaml

from evaluation.baseline_adapter import combined, observations_semgrep, observations_zap
from evaluation.benchmark_freeze import validate as validate_dataset
from schemas.baseline import ScannerProfile

ROOT = Path(__file__).resolve().parents[1]
PROFILE_DIR = ROOT / "benchmarks/baselines-a06-v5"
LABEL = "cft.a06.run"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def input_sha(path):
    """Portable source/config lock; raw scan artifacts still use exact byte hashes."""
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def write(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def command(argv, *, timeout=30, check=True):
    # Explicit minimal environment: provider/API credentials never enter a scanner.
    env = {k: v for k, v in os.environ.items() if k.upper() in {
        "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE",
        "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH", "APPDATA", "LOCALAPPDATA",
    }}
    result = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=timeout, env=env, check=False)
    if check and result.returncode:
        raise RuntimeError(f"{argv[0]} failed ({result.returncode}): {result.stderr[-2000:]}")
    return result


def load_profile(directory=PROFILE_DIR):
    profile = ScannerProfile.model_validate(yaml.safe_load((directory / "profile.yaml").read_text()))
    lock = json.loads((directory / "scanners.lock.json").read_text())
    if (lock.get("schema_version") != "baseline.scanners.lock.a06.v1"
            or lock.get("input_encoding") != "utf8_lf"):
        raise ValueError("Unsupported scanner lock")
    for relative, digest in lock["inputs"].items():
        path = (ROOT / relative).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file() or input_sha(path) != digest:
            raise ValueError("Scanner frozen input mismatch: " + relative)
    required = {p.relative_to(ROOT).as_posix() for p in [
        directory / "profile.yaml", directory / "semgrep-rules.yaml",
        directory / "rules-provenance.json", directory / "RULES-LICENSE.txt",
        ROOT / "evaluation/zap_baseline_worker.py", ROOT / "evaluation/baseline_adapter.py",
        ROOT / "evaluation/semgrep_baseline_worker.py",
        ROOT / "evaluation/scanner_baseline.py", ROOT / "schemas/baseline.py",
        ROOT / "app/scanner_baseline.py", ROOT / "security/source_paths.py",
    ]}
    if set(lock["inputs"]) != required:
        raise ValueError("Scanner lock membership mismatch")
    validate_dataset()
    return profile, lock


def validate_target(target, profile):
    target = Path(target).resolve(strict=True)
    if command(["git", "-C", str(target), "rev-parse", "HEAD"]).stdout.strip() != profile.target_commit:
        raise ValueError("Target must use frozen Juice Shop commit")
    if command(["git", "-C", str(target), "status", "--porcelain", "--untracked-files=all"]).stdout:
        raise ValueError("Target must be clean (including untracked files)")
    records = command(["git", "-C", str(target), "ls-files", "-s", "-z"]).stdout.rstrip("\0").split("\0")
    files = {}
    for record in records:
        mode, _, _, relative = record.split(maxsplit=3)
        path = target / relative
        if mode not in {"100644", "100755"} or path.is_symlink():
            raise ValueError("Only regular target files are accepted")
        if not path.resolve().is_relative_to(target):
            raise ValueError("Target path escaped checkout")
        files[relative] = sha(path)
    # Verify actual worktree bytes, not just clean Git's stat cache. Git hash-object
    # must not execute filters; frozen LF checkout uses raw bytes below.
    for record in records:
        _, blob, _, relative = record.split(maxsplit=3)
        raw = (target / relative).read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if actual != blob:
            raise ValueError("Target bytes differ from pinned Git tree (use LF checkout): " + relative)
    return files


def image_info(image):
    info = json.loads(command(["docker", "image", "inspect", image]).stdout)[0]
    return {"id": info["Id"], "repository_digests": info["RepoDigests"],
            "architecture": info["Architecture"], "os": info["Os"]}


def preflight(target, *, provision_images=False):
    profile, lock = load_profile()
    files = validate_target(target, profile)
    command(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=15)
    images = {}
    for image in [profile.semgrep_image, profile.zap_image, profile.target_image]:
        if provision_images:
            command(["docker", "pull", image], timeout=900)
        images[image] = image_info(image)
    return profile, lock, files, images


def limits(memory="2g", processes="256"):
    return ["--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--cpus=2",
            "--memory=" + memory, "--pids-limit=" + processes,
            "--ulimit", "nofile=4096:4096", "--log-driver=local",
            "--log-opt=max-size=10m", "--log-opt=max-file=2"]


def run_container(argv, name, destination, timeout):
    started = time.monotonic()
    try:
        result = command(argv, timeout=timeout, check=False)
        (destination / "stdout.log").write_text(result.stdout, encoding="utf-8")
        (destination / "stderr.log").write_text(result.stderr, encoding="utf-8")
        return {"exit_code": result.returncode, "timed_out": False,
                "seconds": time.monotonic() - started}
    except subprocess.TimeoutExpired as exc:
        for field in ["stdout", "stderr"]:
            value = getattr(exc, field) or b""
            if isinstance(value, bytes):
                value = value.decode("utf-8", "replace")
            (destination / (field + ".log")).write_text(value, encoding="utf-8")
        return {"exit_code": None, "timed_out": True, "seconds": time.monotonic() - started}
    finally:
        command(["docker", "rm", "-f", name], check=False)


def stage_source(target, destination, expected_files):
    archive_path = destination / "source.tar"
    if expected_files is None:
        raise ValueError("Source staging requires the preflight file digests")
    if len(expected_files) > 20000:
        raise ValueError("Source file limit exceeded")
    total = 0
    with tarfile.open(archive_path, "w") as archive:
        for relative, digest in sorted(expected_files.items()):
            path = target / relative
            if not path.resolve().is_relative_to(target) or path.is_symlink():
                raise ValueError("Unsafe source snapshot path")
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError("Source changed before staging: " + relative)
            total += len(raw)
            if total > 512 * 1024 * 1024:
                raise ValueError("Source byte limit exceeded")
            info = tarfile.TarInfo(relative)
            info.size = len(raw)
            # Deterministic bytes, excluding host metadata and ownership.
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            info.mode = 0o444
            archive.addfile(info, io.BytesIO(raw))
    return archive_path


def sast(target, output, profile, run_id, expected_files=None):
    destination = output / "sast"
    destination.mkdir()
    name = run_id + "-sast"
    archive = stage_source(target, destination, expected_files)
    volume = run_id + "-source"
    write(output / "sast-resources.json", {"volume": volume, "containers": [name, name + "-stage"]})
    command(["docker", "volume", "create", "--label", f"{LABEL}={run_id}", volume])
    args = ["docker", "run", "--name", name, "--label", f"{LABEL}={run_id}",
            "--pull=never", "--network=none", "--read-only", *limits(),
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m", "--env", "HOME=/tmp",
            "--env", "SEMGREP_SEND_METRICS=off", "--env", "SEMGREP_ENABLE_VERSION_CHECK=0",
            "--mount", f"type=volume,src={volume},dst=/src,readonly",
            "--mount", f"type=bind,src={PROFILE_DIR},dst=/rules,readonly",
            "--workdir", "/src", profile.semgrep_image, "semgrep", "scan",
            "--config", "/rules/semgrep-rules.yaml", "--json", "--metrics=off",
            "--disable-version-check", "--no-rewrite-rule-ids", "--jobs=2",
            "--timeout=10", "--max-memory=1024", "--exclude=node_modules",
            "--exclude=.git", "--exclude=dist", "--exclude=build", "."]
    staging = destination / "staging"
    staging.mkdir()
    stage_args = ["docker", "run", "--name", name + "-stage", "--label", f"{LABEL}={run_id}",
                  "--pull=never", "--network=none", "--read-only", *limits(),
                  "--user=0:0",
                  "--env", "CFT_A06_CONTAINER=1",
                  "--mount", f"type=bind,src={archive},dst=/input/source.tar,readonly",
                  "--mount", f"type=volume,src={volume},dst=/src,volume-nocopy",
                  "--mount", (f"type=bind,src={ROOT / 'evaluation/semgrep_baseline_worker.py'},"
                              "dst=/stage.py,readonly"),
                  "--entrypoint", "python3", profile.semgrep_image, "/stage.py"]
    try:
        staged = run_container(stage_args, name + "-stage", staging, 120)
        if staged["exit_code"] != 0:
            raise RuntimeError("Source staging failed; see sast/staging logs")
        result = run_container(args, name, destination, profile.budgets.sast_seconds)
    finally:
        command(["docker", "volume", "rm", volume], check=False)
    result["errors"] = []
    result["coverage_limitations"] = []
    observations = []
    raw_path = destination / "stdout.log"
    try:
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        write(destination / "raw.json", raw)
        observations = observations_semgrep(raw)
        write(destination / "coverage.json", {
            "paths": raw.get("paths", {}), "errors": raw.get("errors", []),
            "version": raw.get("version"), "time": raw.get("time"),
            "exclusions": ["node_modules", ".git", "dist", "build", "Semgrep default ignores"],
        })
        # Scanner-reported warning diagnostics are coverage gaps, not a crashed run.
        # Keep every diagnostic and the original benchmark denominator unchanged.
        if not raw.get("paths", {}).get("scanned"):
            result["errors"].append("Semgrep scanned no files; coverage is unproven")
        for diagnostic in raw.get("errors", []):
            kind = diagnostic.get("type")
            if isinstance(kind, list) and kind:
                kind = kind[0]
            if (diagnostic.get("level") == "warn"
                    and (kind, diagnostic.get("code")) in {
                        ("Syntax error", 3), ("PartialParsing", 3), ("Timeout", 2)}):
                result["coverage_limitations"].append(diagnostic)
            else:
                result["errors"].append("Semgrep technical diagnostic; see coverage.json")
    except (ValueError, KeyError, TypeError) as exc:
        result["errors"].append("Invalid Semgrep output: " + str(exc))
    if result["exit_code"] != 0 or result["timed_out"]:
        result["errors"].append("Semgrep process failed or timed out")
    return result, observations


def dast(output, profile, run_id):
    destination = output / "dast"
    destination.mkdir()
    inputs = output / "scanner-inputs"
    inputs.mkdir()
    write(inputs / "profile.json", profile.model_dump(mode="json"))
    # Output is writable only in this fresh attempt; scanner has no source mount.
    network, target, scanner = run_id + "-net", run_id + "-juice", run_id + "-zap"
    resources = {"network": network, "containers": [target, scanner]}
    write(output / "resources.json", resources)
    command(["docker", "network", "create", "--internal", "--label", f"{LABEL}={run_id}", network])
    result = {"errors": []}
    observations = []
    try:
        command(["docker", "run", "-d", "--name", target, "--label", f"{LABEL}={run_id}",
                 "--pull=never", "--network", network, "--network-alias=juice",
                 *limits("768m", "128"), profile.target_image])
        deadline = time.monotonic() + profile.budgets.startup_seconds
        ready = False
        while time.monotonic() < deadline:
            check = command(["docker", "exec", target, "/nodejs/bin/node", "-e",
                             ("require('http').get('http://127.0.0.1:3000/',r=>"
                             "{r.resume();process.exit(r.statusCode===200?0:1)})"
                             ".on('error',()=>process.exit(1))")], check=False)
            if check.returncode == 0:
                ready = True
                break
            time.sleep(1)
        if not ready:
            raise RuntimeError("Juice Shop readiness timed out")
        budget = profile.budgets
        timeout = (budget.startup_seconds + budget.spider_seconds + budget.ajax_seconds
                   + budget.active_seconds + budget.passive_seconds + 120)
        args = ["docker", "run", "--name", scanner, "--label", f"{LABEL}={run_id}",
                "--pull=never", "--network", network, *limits("2g", "512"),
                "--shm-size=256m", "--env", "CFT_A06_CONTAINER=1",
                "--env", "JAVA_OPTS=-Xmx1024m",
                "--mount", f"type=bind,src={inputs},dst=/input,readonly",
                "--mount", f"type=bind,src={destination},dst=/out",
                "--mount", (f"type=bind,src={ROOT / 'evaluation/zap_baseline_worker.py'},"
                "dst=/driver.py,readonly"), "--entrypoint", "python3", profile.zap_image,
                "/driver.py"]
        result.update(run_container(args, scanner, destination, timeout))
        coverage = json.loads((destination / "coverage.json").read_text())
        result["errors"].extend(coverage["errors"])
        observations, rejected = observations_zap(json.loads((destination / "raw.json").read_text()))
        if rejected:
            result["errors"].append("Out-of-scope alerts rejected: " + str(len(rejected)))
        if result["exit_code"] != 0:
            result["errors"].append("ZAP driver failed or timed out")
    finally:
        logs = command(["docker", "logs", target], check=False)
        (destination / "target.log").write_text(logs.stdout + logs.stderr, encoding="utf-8")
        for name in [scanner, target]:
            command(["docker", "rm", "-f", name], check=False)
        command(["docker", "network", "rm", network], check=False)
        remaining = command(["docker", "ps", "-aq", "--filter", f"label={LABEL}={run_id}"]).stdout
        networks = command(["docker", "network", "ls", "-q", "--filter", f"label={LABEL}={run_id}"]).stdout
        result["cleanup_complete"] = not remaining.strip() and not networks.strip()
        if not result["cleanup_complete"]:
            result["errors"].append("Attempt cleanup incomplete; see resources.json")
    return result, observations


def run_baselines(target, output, *, provision_images=False, retry_of=None):
    output = Path(output).resolve()
    target = Path(target).resolve()
    if output.exists() or output.is_relative_to(target) or target.is_relative_to(output):
        raise ValueError("Use a new output directory outside the target checkout")
    output.mkdir(parents=True)
    run_id = "a06-" + uuid4().hex[:16]
    started = time.monotonic()
    manifest = {"schema_version": "baseline.attempt.a06.v1", "attempt_id": run_id,
                "retry_of": retry_of, "started_at": datetime.now(UTC).isoformat(),
                "status": "TECHNICALLY_INVALID", "technical_errors": [], "coverage_limitations": [],
                "platform": platform.platform(), "components": {},
                "kind": "A06_acceptance_not_A07_measurement", "cleanup_complete": True}
    sast_obs, dast_obs = [], []
    profile = None
    try:
        profile, lock, files, images = preflight(target, provision_images=provision_images)
        manifest.update({"profile": profile.model_dump(mode="json"), "scanner_lock": lock,
                         "images": images, "target_files_sha256": files,
                         "agent_commit": command(["git", "rev-parse", "HEAD"]).stdout.strip(),
                         "agent_dirty": command(["git", "status", "--porcelain"]).stdout.strip(),
                         "dataset_lock_sha256": sha(ROOT / "benchmarks/juice-shop-v20.2.0-v2/dataset.lock.json")})
        write(output / "manifest.json", manifest)
        # Preserve failed SAST and still exercise DAST; never drop a scanner silently.
        for name in ["sast", "dast"]:
            try:
                if name == "sast":
                    result, sast_obs = sast(target, output, profile, run_id, files)
                else:
                    result, dast_obs = dast(output, profile, run_id)
                manifest["components"][name] = result
                manifest["coverage_limitations"].extend(
                    {"component": name, "diagnostic": item}
                    for item in result.get("coverage_limitations", []))
                manifest["technical_errors"].extend(name + ": " + e for e in result["errors"])
                if result.get("cleanup_complete") is False:
                    manifest["cleanup_complete"] = False
            except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
                manifest["components"][name] = {"errors": [str(exc)]}
                manifest["technical_errors"].append(name + ": " + str(exc))
        if files != validate_target(target, profile):
            raise ValueError("Original target changed during measurement")
        manifest["original_unchanged"] = True
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        manifest["technical_errors"].append(f"{type(exc).__name__}: {exc}")
    finally:
        # Audit resources even when target integrity or a scanner failed.
        # A failed Docker query means cleanup is unknown, never successful.
        for kind, argv in {
            "containers": ["docker", "ps", "-aq"],
            "networks": ["docker", "network", "ls", "-q"],
            "volumes": ["docker", "volume", "ls", "-q"],
        }.items():
            try:
                remaining = command([*argv, "--filter", f"label={LABEL}={run_id}"]).stdout.strip()
                if remaining:
                    raise RuntimeError("Owned " + kind + " remain after cleanup")
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                manifest["cleanup_complete"] = False
                manifest["technical_errors"].append("Cleanup audit: " + str(exc))
    # This is an adapter export, never a production Evidence or a Gate decision.
    for name, observations in {"sast": sast_obs, "dast": dast_obs,
                               "union": combined(sast_obs, dast_obs)}.items():
        write(output / (name + "-observations-v2.json"), observations)
    if not manifest["technical_errors"]:
        manifest["status"] = ("COMPLETED_WITH_LIMITATIONS" if manifest["coverage_limitations"]
                              else "COMPLETED")
    manifest["seconds"] = time.monotonic() - started
    manifest["observation_counts"] = {"sast": len(sast_obs), "dast": len(dast_obs),
                                       "union": len(sast_obs) + len(dast_obs)}
    write(output / "manifest.json", manifest)
    (output / "report.md").write_text(render(manifest), encoding="utf-8")
    hashes = {p.relative_to(output).as_posix(): sha(p) for p in output.rglob("*") if p.is_file()}
    write(output / "seal.json", hashes)
    return manifest


def render(manifest):
    lines = ["# A06 scanner baseline acceptance", "", manifest["status"], "",
             "Scanner detections are not independently verified findings.",
             "A07 repeated series and primary benchmark metrics have not been run.", "",
             "Counts: " + json.dumps(manifest.get("observation_counts", {})), "",
             "SAST warning diagnostics: " + str(len(manifest.get("coverage_limitations", []))),
             "All diagnostic details are retained in manifest and sast/coverage.json.",
             "Coverage gaps do not remove cases from the benchmark denominator.", "",
             "Role: anonymous. No authenticated or multi-user workflow coverage.",
             "SAST uses the full frozen language/security pack, including default ignores.",
             "ZAP uses bounded traditional/AJAX spiders and active/passive rules.",
             "Time-limited crawl/active scan is partial coverage; see dast/coverage.json.",
             "Only original samples scanned; patched/synthetic controls were not executed.", "",
             "## Technical errors", ""]
    lines.extend("- " + e for e in manifest["technical_errors"])
    return "\n".join(lines) + "\n"


def score_exports(artifacts, output):
    """Optional A05 hand-off after its branch is merged; never overwrite raw runs."""
    from schemas.benchmark_v2 import BenchmarkDatasetV2, BenchmarkObservationV2

    from evaluation.benchmark_v2 import score_v2

    artifacts, output = Path(artifacts).resolve(), Path(output).resolve()
    if output.exists() or output.is_relative_to(artifacts) or artifacts.is_relative_to(output):
        raise ValueError("Scoring needs a new directory outside the sealed attempt")
    manifest = json.loads((artifacts / "manifest.json").read_text())
    seal = json.loads((artifacts / "seal.json").read_text())
    actual = {p.relative_to(artifacts).as_posix(): sha(p) for p in artifacts.rglob("*")
              if p.is_file() and p.name != "seal.json"}
    if seal != actual:
        raise ValueError("Attempt seal mismatch")
    validate_dataset()
    truth = yaml.safe_load((ROOT / "benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml").read_text())
    if manifest.get("dataset_lock_sha256") != sha(ROOT / "benchmarks/juice-shop-v20.2.0-v2/dataset.lock.json"):
        raise ValueError("Dataset used by attempt differs from current A04")
    # Scanners only saw the original application. Never score patched/synthetic twins.
    truth["cases"] = [c for c in truth["cases"] if c["sample_kind"] == "original"]
    dataset = BenchmarkDatasetV2.model_validate(truth)
    output.mkdir(parents=True)
    for view in ["sast", "dast", "union"]:
        observations = [BenchmarkObservationV2.model_validate(o) for o in json.loads(
            (artifacts / (view + "-observations-v2.json")).read_text())]
        result = score_v2(dataset, observations, technically_valid=manifest["status"] in {
            "COMPLETED", "COMPLETED_WITH_LIMITATIONS"},
                          technical_errors=manifest["technical_errors"])
        write(output / (view + "-score-v2.json"), result.model_dump(mode="json"))
    write(output / "coverage-limitations.json", manifest.get("coverage_limitations", []))
    return output
