"""One fresh search and one C04 campaign per supported family; no repeat series."""
from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from time import monotonic

from agent.llm import ProviderFailoverClient, parse_route_specs
from app import research_diagnostic_run
from app.config import Settings
from app.delivery_metrics import ROOT, aggregate_search, percent, rubric_text
from app.research_score import score_research
from fix_verification.measurement import statistics
from fix_verification.repair_loop import run as repair_run
from fix_verification.repair_replay import replay
from fix_verification.scope import load_scope
from reporting.checkpoints import write_json
from schemas.repair_loop import RepairLimits
from security.error_redaction import redact_error_message


def select_families(score_directory, specs):
    """Evaluator matching selects work; no benchmark labels enter C04 model context."""
    cases = {}
    for split in ("development", "holdout"):
        scored = json.loads((score_directory / f"{split}-agent.json").read_bytes())
        cases.update({row["case_id"]: row for row in scored["cases"]})
    return [{"family": spec.id, "case_ids": spec.case_ids,
             "current_confirmed": all(cases.get(case, {}).get("confirmation_supported") is True
                                      for case in spec.case_ids),
             "current_case_evidence": {case: cases.get(case, {}) for case in spec.case_ids}}
            for spec in specs]


def seal(output):
    write_json(output / "seal.json", {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
               for p in sorted(output.rglob("*")) if p.is_file() and p != output / "seal.json"})


def render(result):
    search, repairs = result.get("search"), result["repairs"]
    lines = ["# Один свежий проход поиска и исправлений", "",
             f'Статус: {result["status"]}. Повторная серия не запускалась.', ""]
    if search:
        lines += ["| Метрика | Результат |", "|---|---|",
            f'| Precision подтверждений в эталоне | {percent(search["confirmed_precision"])} |',
            f'| Recall подтверждений | {percent(search["confirmed_recall"])} |',
            f'| Доля ложных подтверждений безопасных случаев | {percent(search["false_confirmation_rate"])} |',
            f'| Точность вынесенных бинарных вердиктов | {percent(search["verdict_accuracy_on_decisions"])} |',
            f'| Покрытие бинарными вердиктами | {percent(search["decision_coverage"])} |',
            f'| Recall обнаружения | {percent(search["detection_recall"])} |',
            f'| SAST без агента: Recall обнаружения | {percent(search["sast_detection_recall"])} |',
            f'| Точность серьезности | {rubric_text(search, "severity")} |',
            f'| Точность Context Priority | {rubric_text(search, "context_priority")} |', ""]
    lines += ["| Исправление | Исход | Причина |", "|---|---|---|"]
    lines += [f'| {row["family"]} | {row["status"]} | {row.get("stop_reason", "")} |'
              for row in repairs]
    timing = result["laboratory_time_admitted_confirmed_case_to_verified_patch"]
    lines += ["", f'Лабораторное время до проверенного патча: n={timing["n"]}, '
              + (f'среднее {timing["mean_ms"] / 1000:.3f} с.' if timing["n"] else "N/A, успехов нет."),
              "Время включает C04 генерацию, проверки и очистку после приема подтвержденного",
              "случая. Это отдельный fix-срез на той же закрепленной версии, с защищенными",
              "C01/B09 входами и свежими BEFORE/AFTER проверками C03. C04 не изменяет исходный",
              "отчет поиска, исходный проект или общий CI Gate. Исторические доказательства",
              "C01 используются C04 согласно его контракту; новые evidence не подменяются.", "",
              "Эксплуатационный MTTR: N/A. Воспроизводимость: не измеряем.",
              "Эталон: 27 уязвимых и 8 безопасных original-случаев A04; известный DEV-корпус.",
              "Precision ограничен сопоставленными эталону подтверждениями. Внеэталонные",
              "находки не считаются автоматически ложными. Нулевой FPR при отсутствии",
              "решений по безопасным случаям не доказывает их успешное отклонение.", ""]
    return "\n".join(lines)


def execute(args):
    config = Settings(_env_file=args.env_file) if args.env_file else Settings()
    research_diagnostic_run.settings = config
    source = args.checkout.resolve(strict=True)
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError("Single pass needs a fresh output outside the target")
    # Preflight before any measured work: a bad token must not start a search or repair.
    checked = research_diagnostic_run.preflight(source, args.image, args.browser_image, probe_model=True)
    if checked["status"] == "blocked":
        print(json.dumps({"status": "blocked", "generation": checked["generation"]}))
        return 2
    specs, _ = load_scope()
    output.mkdir(parents=True)
    result = {"schema_version": "cft.single-pass-measurement.v1", "status": "started",
              "started_at": datetime.now(UTC).isoformat(), "search": None, "repairs": [],
              "reproducibility_measured": False, "new_search_runs": 1,
              "production_mttr": None, "planned_families": [spec.id for spec in specs],
              "laboratory_time_admitted_confirmed_case_to_verified_patch": statistics([])}
    write_json(output / "preflight.json", checked)
    try:
        limits = research_diagnostic_run.limits(max_http_requests=2048)
        limits = limits.model_copy(update={"wall_seconds": args.search_seconds})
        research_diagnostic_run.run(source, args.image, args.browser_image, output / "search",
                                    campaign_limits=limits)
        raw = score_research(output / "search", ROOT / "benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml",
                             output / "search-score")
        result.update(search=aggregate_search(raw), search_degraded=raw["research_degraded"])
        selected = select_families(output / "search-score", specs)
        write_json(output / "repair-selection.json", selected)
        client = ProviderFailoverClient(routes=parse_route_specs("nsu:qwen3.8-flash-next",
            allow_external_fallbacks=False), credentials=config.llm_provider_credentials(),
            timeout_seconds=45, max_output_tokens=3072, reasoning_effort="low", trace=False)
        for selection in selected:
            row = {**selection, "status": "INELIGIBLE", "stop_reason": "not_confirmed_in_current_search",
                   "duration_ms": None, "verified_ms": None,
                   "source_snapshot_sha256": checked["target"]["files_sha256"],
                   "search_seal_sha256": sha256((output / "search/seal.json").read_bytes()).hexdigest()}
            result["repairs"].append(row)
            if not selection["current_confirmed"]:
                continue
            row.update(status="STARTED", started_at=datetime.now(UTC).isoformat())
            write_json(output / (selection["family"] + "-started.json"), row)
            started = monotonic()
            try:
                directory = output / "repairs" / selection["family"]
                repair_run(target=source, family=selection["family"], output=directory, client=client,
                    limits=RepairLimits(max_attempts=1, wall_clock_seconds=900), fix_image=args.fix_image)
                row.update(replay(directory))
                row["duration_ms"] = int((monotonic() - started) * 1000)
                if row["status"] == "FIXED":
                    row["verified_ms"] = row["duration_ms"]
            except (ValueError, OSError, RuntimeError) as exc:
                row.update(status="TECHNICAL_ERROR", stop_reason=type(exc).__name__,
                           error=redact_error_message(exc), duration_ms=int((monotonic() - started) * 1000))
            finally:
                if row["status"] == "STARTED":
                    row.update(status="INTERRUPTED", stop_reason="interrupted_before_final_replay",
                               duration_ms=int((monotonic() - started) * 1000))
                row["finished_at"] = datetime.now(UTC).isoformat()
                write_json(output / (selection["family"] + "-receipt.json"), row)
                print(json.dumps({"family": row["family"], "status": row["status"],
                                  "duration_ms": row["duration_ms"]}), flush=True)
        result["status"] = "completed_with_limitations" if result["search_degraded"] or any(
            row["status"] != "FIXED" for row in result["repairs"]) else "completed"
    except BaseException as exc:
        result.update(status="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed",
                      failure_type=type(exc).__name__)
        raise
    finally:
        result["laboratory_time_admitted_confirmed_case_to_verified_patch"] = statistics(
            [row["verified_ms"] for row in result["repairs"] if row.get("verified_ms") is not None])
        result["finished_at"] = datetime.now(UTC).isoformat()
        write_json(output / "metrics.json", result)
        (output / "report.md").write_text(render(result))
        seal(output)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--browser-image", required=True)
    parser.add_argument("--fix-image", default="cft-fix-juice:stage1")
    parser.add_argument("--search-seconds", type=int, default=1800)
    args = parser.parse_args()
    if args.search_seconds <= 0 or args.search_seconds > 1800:
        parser.error("Search budget must be 1..1800 seconds")
    return execute(args)


if __name__ == "__main__":
    raise SystemExit(main())
