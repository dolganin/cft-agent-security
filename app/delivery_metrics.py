"""Offline delivery joining a sealed search run and the separate C05 repair cohort."""
from __future__ import annotations

import argparse
import json
import math
import tempfile
import zipfile
from hashlib import sha256
from pathlib import Path, PurePosixPath

from app.research_score import score_research
from fix_verification.measurement import replay_series, statistics
from fix_verification.repair_replay import replay

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_bytes())


def ratio(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else None}


def aggregate_search(summary):
    """Pool independent case counts, never average split percentages."""
    splits = list(summary["metrics"].values())
    counts = {key: sum(s["verification"]["counts"][key] for s in splits)
              for key in splits[0]["verification"]["counts"]}
    detection = {key: sum(s["detection"][key] for s in splits)
                 for key in ("tp", "fp", "fn", "tn")}
    baseline = {key: sum(s["sast_detection"][key] for s in splits)
                for key in ("tp", "fp", "fn", "tn")}
    return {
        "counts": counts, "detection_counts": detection,
        "confirmed_precision": ratio(counts["correct_confirmations"], counts["confirmed_cases"]),
        "confirmed_recall": ratio(counts["correct_confirmations"], counts["positive_cases"]),
        "false_confirmation_rate": ratio(counts["false_confirmations"], counts["negative_cases"]),
        "decided_safe_fpr": ratio(counts["false_confirmations"],
                                 counts["false_confirmations"] + counts["correct_rejections"]),
        "verdict_accuracy_on_decisions": ratio(counts["correct_decisions"], counts["decided_cases"]),
        "decision_coverage": ratio(counts["decided_cases"], counts["labeled_cases"]),
        "detection_recall": ratio(detection["tp"], detection["tp"] + detection["fn"]),
        "detection_precision": ratio(detection["tp"], detection["tp"] + detection["fp"]),
        "sast_detection_recall": ratio(baseline["tp"], baseline["tp"] + baseline["fn"]),
        "sast_detection_precision": ratio(baseline["tp"], baseline["tp"] + baseline["fp"]),
        "severity_accuracy": summary["severity_accuracy"],
        "context_priority_accuracy": summary["context_priority_accuracy"],
        "reproducibility": {"value": None, "reason": "not_measured_by_user_request"},
        "outside_observations_are_not_automatic_false_positives": True,
    }


def verify_files(root, files):
    for name, expected in files.items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name or ":" in name:
            raise ValueError("Unsafe sealed file path")
        path = (root / name).resolve(strict=True)
        if not path.is_relative_to(root.resolve()) or sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("Delivery input seal mismatch: " + name)


def extract_run(archive, destination):
    """Bounded ZIP extraction; replay validates the full C04 receipt chain next."""
    with zipfile.ZipFile(archive) as zipped:
        names = zipped.namelist()
        if len(names) != len(set(names)) or len(names) > 10000:
            raise ValueError("Duplicate or excessive repair ZIP membership")
        if sum(info.file_size for info in zipped.infolist()) > 128 * 1024 * 1024:
            raise ValueError("Repair ZIP exceeds extraction budget")
        for info in zipped.infolist():
            path = PurePosixPath(info.filename)
            if (path.is_absolute() or ".." in path.parts or "\\" in info.filename
                    or ":" in info.filename or (info.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError("Unsafe repair ZIP member")
        zipped.extractall(destination)


def repair_projection(directory):
    directory = directory.resolve(strict=True)
    verify_files(directory, read(directory / "projection-seal.json")["files"])
    report = read(directory / "measurement.json")
    protocol = read(directory / "protocol.json")
    original_seal = read(directory / "original-series-seal.json")["files"]
    protocol_hash = sha256((directory / "protocol.json").read_bytes()).hexdigest()
    if report["protocol_sha256"] != protocol_hash or original_seal["protocol.json"] != protocol_hash:
        raise ValueError("C05 protocol binding mismatch")
    if original_seal["measurement.json"] != sha256((directory / "measurement.json").read_bytes()).hexdigest():
        raise ValueError("C05 measurement binding mismatch")
    rows = report["rows"]
    if [(r["id"], r["family"], r["repetition"]) for r in rows] != [
            (r["id"], r["family"], r["repetition"]) for r in protocol["slots"]]:
        raise ValueError("C05 rows do not match the planned cohort")
    times = []
    replays = []
    for row in rows:
        if row["status"] == "FIXED":
            value = row["verified_ms"]
            if type(value) is not int or value < 0 or value != row["duration_ms"]:
                raise ValueError("Invalid C05 success duration")
            times.append(value)
        archive = directory / (row["id"] + ".zip")
        if archive.is_file():
            with tempfile.TemporaryDirectory(prefix="cft-c05-delivery-") as temporary:
                destination = Path(temporary)
                extract_run(archive, destination)
                checked = replay(destination)
                saved = read(destination / "result.json")
                if (checked["status"] != row["status"]
                        or checked["seal_sha256"] != row["seal_sha256"]
                        or checked["attempts"] != row["attempts"]
                        or saved["family"] != row["family"]
                        or saved["original_unchanged"] != row["original_unchanged"]):
                    raise ValueError("C05 row does not match its C04 replay")
                replays.append({"slot_id": row["id"], **checked})
    calculated = statistics(times)
    if (set(calculated) != set(report["time_confirmed_input_to_verified"])
            or any(not math.isclose(value, report["time_confirmed_input_to_verified"][key])
                   for key, value in calculated.items() if value is not None)
            or report["verified_eligible"]["verified"] != len(times)
            or report["verified_eligible"]["eligible"] != len(rows)):
        raise ValueError("C05 aggregate disagrees with all planned rows")
    return {"measurement": report, "validation": "sealed_public_projection_with_partial_run_replay",
            "complete_series_replayed": False, "locally_replayed_slots": replays,
            "missing_full_run_slots": [r["id"] for r in rows if r["id"] not in
                                       {item["slot_id"] for item in replays}],
            "source": str(directory), "same_execution_as_search": False}


def historical_baseline(directory):
    """Use one archived A06 run; preserve the distinction from fresh SAST."""
    directory = directory.resolve(strict=True)
    verify_files(directory, read(directory / "seal.json"))
    result = {"source": str(directory), "run": "run-01", "historical": True,
              "new_scan": False, "metrics": {}}
    for kind in ("sast", "dast", "union"):
        splits = [read(directory / f"baseline/run-01-{kind}-{split}.json")
                  for split in ("development", "holdout")]
        counts = {key: sum(s["detection"][key] for s in splits)
                  for key in ("tp", "fp", "fn", "tn")}
        result["metrics"][kind] = {"counts": counts,
            "detection_recall": ratio(counts["tp"], counts["tp"] + counts["fn"]),
            "detection_precision": ratio(counts["tp"], counts["tp"] + counts["fp"])}
    return result


def percent(metric):
    if metric["value"] is None:
        return "N/A"
    return f'{metric["value"] * 100:.2f}% ({metric["numerator"]}/{metric["denominator"]})'


def render(data):
    search, repair = data["search"], data["repair"]
    baseline = data["historical_a06_baseline"]["metrics"]
    timing = repair["measurement"]["time_confirmed_input_to_verified"]
    return "\n".join([
        "# Метрики CFT Security Agent для Беспалова", "",
        "Juice Shop v20.2.0, commit 5658473cf8814459bf89000ce373b20ed0b4eb37.",
        "Эталон A04: 27 уязвимых и 8 безопасных случаев original. Это выбранный проверенный",
        "набор случаев, а не все задания Juice Shop. Поиск измерен одним сохраненным запуском",
        "Qwen 3.8 Flash Next с SAST, source detectors и зарегистрированными проверками.", "",
        "| Метрика | Результат |", "|---|---|",
        f'| Precision подтверждений в эталоне | {percent(search["confirmed_precision"])} |',
        f'| Recall подтверждений | {percent(search["confirmed_recall"])} |',
        f'| Ложные подтверждения безопасных случаев | {percent(search["false_confirmation_rate"])} |',
        f'| Точность вынесенных бинарных вердиктов | {percent(search["verdict_accuracy_on_decisions"])} |',
        f'| Покрытие бинарными вердиктами | {percent(search["decision_coverage"])} |',
        f'| Recall обнаружения | {percent(search["detection_recall"])} |',
        f'| Precision обнаружения | {percent(search["detection_precision"])} |',
        f'| SAST без агента: Recall обнаружения | {percent(search["sast_detection_recall"])} |',
        f'| SAST без агента: Precision обнаружения | {percent(search["sast_detection_precision"])} |',
        "| Точность серьезности | N/A: совместимые оценки в этом запуске отсутствуют |",
        "| Точность Context Priority | N/A: независимой разметки CP нет |",
        f'| Исторический A06 SAST: Recall обнаружения | {percent(baseline["sast"]["detection_recall"])} |',
        f'| Исторический A06 DAST: Recall обнаружения | {percent(baseline["dast"]["detection_recall"])} |',
        f'| Исторический A06 SAST + DAST: Recall обнаружения | {percent(baseline["union"]["detection_recall"])} |',
        f'| Лабораторное время confirmed-input -> verified patch, C05 | {timing["mean_ms"] / 1000:.3f} с, n={timing["n"]} |',
        "| Эксплуатационный MTTR | N/A: исправления не внедрялись в эксплуатацию |",
        "| Воспроизводимость | Не измеряем по согласованному объему |", "",
        "Precision относится к подтверждениям, сопоставленным эталону. Находки вне эталона",
        "не считаются автоматически ложными. На безопасных случаях нет бинарных решений:",
        "0/8 - наблюдаемая доля ложных подтверждений, а FPR среди решенных безопасных случаев - N/A.",
        "Точность 100% относится только к вынесенным решениям, покрытие указано отдельно.", "",
        "A06 baseline взят из первого сохраненного запуска 13 октября на той же версии",
        "Juice Shop и original-эталоне, с историческими правилами и анонимным DAST.",
        "В новом поиске SAST расширен, а проверки используют дополнительные роли и сценарии.",
        "Это сравнение зарегистрированных конфигураций; их бюджеты и доступы различаются.",
        "Baseline измеряет обнаружение; Recall подтверждений агента - отдельная метрика.", "",
        "C05 - отдельная ранее выполненная командой серия: два случая (SQL search и redirect),",
        "по три исправления каждого, всего 6/6 успешных case-runs. Это два уникальных случая,",
        "а не шесть разных уязвимостей. Время включает генерацию, проверки, повторы и очистку.",
        "Эта серия начиналась от исторического B09 (2 eligible из 5 confirmed) и не является",
        "измерением автоматического исправления всех 13 подтверждений нового запуска.",
        (f'Проверка C05: {repair["validation"]}; локально воспроизведено из артефактов '
         f'{len(repair["locally_replayed_slots"])} отдельных SQL-исполнения.'),
        ("Полная серия независимо перепроверена из полного пакета."
         if repair["complete_series_replayed"] else
         "Значение по всем шести взято из проверенной по SHA256 сводки команды; полный replay "
         "всей серии требует полного C05 пакета, публичная проекция его не заменяет."), "",
        "Последний поиск остановлен по бюджету (30 мин 45 с), имеет degraded-статус и одну",
        "ошибку провайдера. Известный корпус использовался при разработке; результаты",
        "не характеризуют независимый holdout или качество на других проектах.", "",
        "Повторный живой запуск и новая серия воспроизводимости для этой сводки не выполнялись.", "",
        "Пересчет: `python -m app.delivery_metrics --search-run <sealed-run> --output <new-directory>`.", "",
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--search-run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repair-projection", type=Path, default=ROOT / "docs/evidence/c05")
    parser.add_argument("--repair-series", type=Path)
    parser.add_argument("--historical-baseline", type=Path,
                        default=ROOT / "artifacts/a08-final-2026-10-13-v3")
    args = parser.parse_args()
    output = args.output.resolve()
    inputs = [args.search_run.resolve(), args.repair_projection.resolve(), args.historical_baseline.resolve()]
    if args.repair_series:
        inputs.append(args.repair_series.resolve())
    if output.exists() or any(output.is_relative_to(path) or path.is_relative_to(output) for path in inputs):
        parser.error("Output must be fresh and disjoint from sealed inputs")
    repair = repair_projection(args.repair_projection)
    baseline = historical_baseline(args.historical_baseline)
    if args.repair_series:
        complete = replay_series(args.repair_series.resolve())
        if complete != repair["measurement"]:
            raise ValueError("Complete C05 series disagrees with its public projection")
        repair.update(validation="complete_series_replayed", complete_series_replayed=True,
                      missing_full_run_slots=[])
    output.mkdir(parents=True)
    raw = score_research(args.search_run, ROOT / "benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml",
                         output / "search-rescore")
    data = {"schema_version": "cft.delivery-metrics.v1", "search": aggregate_search(raw),
            "search_run": str(args.search_run.resolve()), "search_run_replayed": True,
            "search_degraded": raw["research_degraded"], "repair": repair,
            "historical_a06_baseline": baseline,
            "new_live_runs": 0, "reproducibility_measured": False}
    (output / "metrics.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    (output / "report.md").write_text(render(data))
    (output / "seal.json").write_text(json.dumps({p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
        for p in sorted(output.rglob("*")) if p.is_file()}, indent=2) + "\n")
    print(json.dumps({"output": str(output), "precision": data["search"]["confirmed_precision"],
                      "recall": data["search"]["confirmed_recall"],
                      "repair_validation": repair["validation"]}))


if __name__ == "__main__":
    main()
