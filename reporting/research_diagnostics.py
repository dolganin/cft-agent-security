"""Offline operational readout of saved research data, never benchmark scoring."""
import json
from collections import Counter, defaultdict
from pathlib import Path


def read_json(path, default):
    return json.loads(path.read_text()) if path.is_file() else default


def saved_campaign_diagnostics(output):
    output = Path(output)
    summaries = []
    incomplete = []
    questions = read_json(output / "questions.json", [])
    question_lookup = {row["id"]: row for row in questions}
    for saved_report in read_json(output / "reports.json", []):
        identifier = saved_report["question_id"]
        if identifier not in question_lookup:
            finding = saved_report.get("research_report", saved_report.get("report", {})).get("finding", {})
            source = finding.get("source")
            question_lookup[identifier] = {"finding": finding, "is_candidate": saved_report.get("is_candidate"),
                "origin": {"surface_question": "surface", "model_scout": "model", "semgrep": "sast"}.get(source)}
    for directory in sorted((output / "questions").glob("*"), key=lambda p: int(p.name)):
        summary = read_json(directory / "summary.json", None)
        progress = read_json(directory / "progress.json", {})
        if summary and summary.get("completed", True):
            summaries.append({"directory": directory.name, **summary})
        else:
            incomplete.append({"directory": directory.name, "summary": summary,
                "model_calls": progress.get("model_calls", 0), "ledger_entries": len(progress.get("ledger", []))})
    runtime = read_json(output / "canonical-runtime-reviews.json", [])
    proof_groups = defaultdict(list)
    pending = []
    for row in runtime:
        if row["status"] == "confirmed":
            binding = row.get("binding", {})
            # Same fixed protocol/handler is a repeated proof unit. This is NOT
            # an assertion that all possible sinks in the handler are one cause.
            key = tuple(binding.get(k) for k in ("source_snapshot", "route_id", "handler_id", "family", "tool", "endpoint"))
            proof_groups[key].append(row["finding_id"])
        else:
            question = question_lookup.get(row["finding_id"], {})
            pending.append({"finding_id": row["finding_id"], "status": row["status"],
                "reason": row.get("reason"), "is_candidate": question.get("is_candidate"),
                "origin": question.get("origin"), "file": question.get("finding", {}).get("file")})
    source_groups = defaultdict(list)
    for finding in read_json(output / "findings.json", []):
        if finding.get("line_start") is not None:
            source_groups[(finding["file"], finding["line_start"], finding.get("line_end"))].append(finding["id"])
    ledger = []
    turns = []
    for directory in (output / "questions").glob("*"):
        progress = read_json(directory / "progress.json", {})
        ledger.extend(progress.get("ledger", []))
        turns.extend(progress.get("turns", []))
    operations = Counter((item.get("tool"), json.dumps(item["request_summary"], sort_keys=True))
                         for item in ledger if item.get("request_summary"))
    attempts = output.parent / "llm-attempts.jsonl"
    logs = [json.loads(line) for line in attempts.read_text().splitlines()] if attempts.exists() else []
    latencies = sorted(row["latency_ms"] for row in logs if row.get("latency_ms") is not None)
    return {"schema": "cft.research.operational-diagnostics.v1", "benchmark_measurement": False,
        "security_verdicts_revalidated": False, "campaign_completed": read_json(output / "summary.json", {}).get("completed", False),
        "questions_completed": len(summaries), "incomplete_questions": incomplete,
        "model_calls_completed_questions": sum(row.get("model_calls", 0) for row in summaries),
        "actions_completed_questions": sum(row.get("actions", 0) for row in summaries),
        "question_stop_counts": dict(Counter(row.get("stop_reason") for row in summaries)),
        "persisted_runtime_status_counts": dict(Counter(row["status"] for row in runtime)),
        "confirmed_protocol_handler_groups": [{"binding_key": list(key), "finding_ids": ids}
            for key, ids in proof_groups.items()],
        "confirmed_protocol_handler_group_count": len(proof_groups),
        "group_count_is_not_unique_vulnerability_count": True,
        "pending_reason_counts": dict(Counter(row.get("reason") for row in pending)), "pending_cases": pending,
        "same_location_candidates": [{"file": k[0], "line_start": k[1], "line_end": k[2], "finding_ids": v}
            for k, v in source_groups.items() if len(v) > 1],
        "cross_question_repeated_operations": [{"tool": k[0], "parameters": json.loads(k[1]), "count": count}
            for k, count in operations.items() if count > 1],
        "tool_counts": dict(Counter(row.get("tool") for row in ledger)),
        "turns": len(turns), "llm_log_status_counts": dict(Counter(row.get("status") for row in logs)),
        "llm_latency_ms": {"median": latencies[len(latencies)//2] if latencies else None,
            "max": max(latencies, default=None),
            "note": "Route attempt latency includes correction time; summing logs double-counts correction requests"},
        "timing": {"completed_question_seconds": sum(row.get("elapsed_seconds", 0) for row in summaries),
            "recorded_stage_seconds": read_json(output / "timings.json", {}),
            "historical_stage_timing_available": any("elapsed_seconds" in row for row in summaries)}}
