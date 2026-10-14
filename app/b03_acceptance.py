"""Bounded source-only SAST/Scout comparison; never executes target application code."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path

from dotenv import dotenv_values

from agent.llm_model import FallbackLLMAgentModel
from agent.repository_scout import RepositoryScout
from app.config import settings
from app.measurement_manifest import manifest
from discovery.express_routes import build_express_source_map, link_candidates_to_routes
from discovery.scout import merge_scout_candidates
from discovery.service import ProjectDiscovery
from pipeline.subprocess_runner import run_cancellable_process
from sast.normalizer import normalize_semgrep_payload
from sast.semgrep_runner import _DOCKER_SEMGREP_IMAGE, _docker_command
from scripts.a08_finalize import sha, write
from tools.repository_source import RepositorySource

TARGET_COMMIT = "5658473cf8814459bf89000ce373b20ed0b4eb37"
RULES = Path("benchmarks/baselines-a06-v5/semgrep-rules.yaml")


def snapshot(target):
    revision = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    if revision != TARGET_COMMIT:
        raise ValueError("Target must be pinned Juice Shop v20.2.0")
    dirty = subprocess.run(["git", "-C", str(target), "status", "--porcelain", "--untracked-files=no"],
                           capture_output=True, text=True, check=True).stdout
    if dirty:
        raise ValueError("Target tracked source is modified")
    paths = subprocess.run(["git", "-C", str(target), "ls-files"],
                           capture_output=True, text=True, check=True).stdout.splitlines()
    hashes = {}
    for path in paths:
        local = target / path
        if local.is_symlink() or not local.resolve().is_relative_to(target):
            raise ValueError("Target snapshot contains unsafe paths")
        if local.is_file():
            hashes[path] = sha(local)
    return {"commit": revision, "files": hashes,
            "digest": hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()}


class RecordingClient:
    def __init__(self, client, destination):
        self.client, self.destination, self.turn = client, destination, 0

    def __getattr__(self, name):
        return getattr(self.client, name)

    def complete_model(self, **kwargs):
        self.turn += 1
        payload = kwargs["user_payload"]
        submitted = {k: payload[k] for k in (
            "source_snippets", "previous_context", "search_results", "related_files",
            "route_inventory", "remaining_turns", "remaining_candidate_budget",
        )}
        write(self.destination / f"turn-{self.turn:02d}-input.json", submitted)
        try:
            result = self.client.complete_model(**kwargs)
        except Exception as exc:
            write(self.destination / f"turn-{self.turn:02d}-failure.json",
                  {"category": type(exc).__name__,
                   "schema_errors": getattr(self.client, "last_schema_errors", [])})
            raise
        write(self.destination / f"turn-{self.turn:02d}-output.json", result.model_dump(mode="json"))
        return result


def run(target, output, model, max_turns=8, sast_from=None):
    target, output = Path(target).resolve(), Path(output).resolve()
    if output.exists() or output.is_relative_to(target):
        raise ValueError("Output must be fresh and outside target")
    before = snapshot(target)
    discovery = ProjectDiscovery().discover(target)
    source = RepositorySource(discovery)
    if any(p not in before["files"] for p in source.files):
        raise ValueError("Scout corpus must belong to pinned tracked source")
    config = settings.model_copy(update={
        "agent_mode": "llm", "llm_routes": "nsu:" + model,
        "llm_allow_external_fallbacks": False, "llm_reasoning_effort": "low",
        "llm_max_output_tokens": 4096, "llm_timeout_seconds": 75,
        "scout_max_turns": max_turns, "scout_max_source_chars": 160000,
        "scout_max_candidates": 32, "scout_wall_clock_seconds": 600,
    })
    identity = manifest(config)
    output.mkdir(parents=True)
    write(output / "implementation.json", identity)
    write(output / "snapshot.json", before)
    write(output / "corpus.json", {
        "files": {p: before["files"].get(p) for p in source.files}, "skipped": source.skipped,
        "selection": "trusted Discovery application inventory; no benchmark labels or anchors",
    })
    # Operator-owned scanner, read-only target, immutable image, no network.
    command = _docker_command(target, RULES.resolve())
    command[2:2] = ["--cpus=2", "--memory=2g", "--pids-limit=128"]
    started = time.monotonic()
    if sast_from is None:
        scanned = run_cancellable_process(command, cwd=target, timeout=600)
        if scanned.returncode:
            write(output / "scanner-failure.json", {"exit_code": scanned.returncode})
            raise ValueError("SAST failed; no successful comparison claimed")
        raw = json.loads(scanned.stdout)
        scanner_manifest = {
            "image": _DOCKER_SEMGREP_IMAGE, "rules_sha256": sha(RULES),
            "original_stdout_sha256": hashlib.sha256(scanned.stdout.encode()).hexdigest(),
            "seconds": round(time.monotonic() - started, 3), "exit_code": scanned.returncode,
        }
    else:
        previous = Path(sast_from).resolve()
        if read_json(previous / "snapshot.json") != before:
            raise ValueError("Cached SAST target snapshot mismatch")
        scanner_manifest = read_json(previous / "sast/manifest.json")
        if (scanner_manifest["image"] != _DOCKER_SEMGREP_IMAGE
                or scanner_manifest["rules_sha256"] != sha(RULES)
                or scanner_manifest["exit_code"] != 0):
            raise ValueError("Cached scanner identity/status mismatch")
        raw = read_json(previous / "sast/raw-redacted.json")
        scanner_manifest = {**scanner_manifest, "reused_from": previous.name,
                            "reuse_raw_sha256": sha(previous / "sast/raw-redacted.json")}
    if not isinstance(raw.get("results"), list):
        raise TypeError("Invalid scanner output")
    if any(e.get("level", "").lower() == "error" for e in raw.get("errors", [])):
        write(output / "scanner-failure.json", {"status": "fatal_scanner_diagnostic"})
        raise ValueError("Scanner diagnostics prevent acceptance")
    findings = normalize_semgrep_payload(raw, repository_root=target,
                                        service_resolver=lambda _path: "juice", scanner_root="/src")
    if sast_from is not None and [f.model_dump(mode="json") for f in findings] != read_json(
        Path(sast_from) / "sast/findings.json",
    ):
        raise ValueError("Cached normalized SAST differs from source-bound recomputation")
    # Do not publish scanner code snippets/literals; locations and rules unchanged.
    for item in raw["results"]:
        if "lines" in item.get("extra", {}):
            item["extra"]["lines"] = "<source-snippet-not-published>"
    write(output / "sast/raw-redacted.json", raw)
    write(output / "sast/findings.json", [f.model_dump(mode="json") for f in findings])
    write(output / "sast/manifest.json", {**scanner_manifest,
          "diagnostics": raw.get("errors", []), "redaction": "extra.lines only"})
    source_map = build_express_source_map(discovery)
    write(output / "express-source-map.json", source_map.model_dump(mode="json"))
    for mode in ("round_robin", "handlers"):
        destination = output / mode
        mode_config = config.model_copy(update={
            "executor_audit_log": destination / "audit/executor.jsonl",
        })
        client = FallbackLLMAgentModel.from_settings(mode_config).client
        # Prefer the current ignored local key over a stale inherited shell key.
        local = dotenv_values(".env").get("NSU_OPENWEBUI_KEY")
        if local:
            client.credentials["NSU_OPENWEBUI_KEY"] = local
        recording = RecordingClient(client, destination / "turns")
        scout = RepositoryScout(
            recording, max_turns=max_turns, max_source_chars=config.scout_max_source_chars,
            max_candidates=config.scout_max_candidates, wall_clock_seconds=config.scout_wall_clock_seconds,
            schedule_mode=mode, on_progress=lambda e, m=mode: print(json.dumps({"mode": m, **e}), flush=True),
        )
        batch = scout.scout(discovery, source_map=source_map)
        merged, duplicates = merge_scout_candidates(findings, batch.candidates,
                                                   service_resolver=lambda _p: "juice",
                                                   repository_root=target)
        write(destination / "summary.json", {**scout.audit, "duplicates": duplicates,
              "sast_queue": len(findings), "combined_queue": len(merged), "verification_run": False})
        write(destination / "candidates.json", batch.model_dump(mode="json"))
        write(destination / "findings.json", [f.model_dump(mode="json") for f in merged])
        write(destination / "route-links.json", link_candidates_to_routes(batch.candidates, source_map))
        if scout.audit["stop_reason"] == "model_unavailable":
            raise ValueError("Model failed; preserve failed attempt, do not claim acceptance")
    after = snapshot(target)
    if before != after or identity["identity_sha256"] != manifest(config)["identity_sha256"]:
        raise ValueError("Inputs changed during measurement")
    write(output / "completion.json", {"status": "discovery_comparison_completed",
          "source_unchanged": True, "implementation_unchanged": True,
          "ground_truth_given_to_model": False, "runtime_verification": False})
    write(output / "seal.json", {p.relative_to(output).as_posix(): sha(p)
                                 for p in output.rglob("*") if p.is_file()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", choices=["qwen3.8-flash-next", "Qwen3.8-27B"],
                        default="qwen3.8-flash-next")
    parser.add_argument("--max-turns", type=int, choices=range(1, 17), default=8)
    parser.add_argument("--sast-from", type=Path,
                        help="Reuse measured SAST only after snapshot/config and normalization checks")
    args = parser.parse_args()
    run(args.target, args.output, args.model, args.max_turns, args.sast_from)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
