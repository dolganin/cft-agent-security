"""Produce a separate operational report without rewriting saved research Evidence."""
import argparse
import json
from hashlib import sha256
from pathlib import Path

from reporting.research_diagnostics import saved_campaign_diagnostics


def recover(source, output):
    source, output = Path(source).resolve(), Path(output).resolve()
    if output.exists():
        raise FileExistsError("Choose a fresh diagnostic output")
    if output == source or source in output.parents:
        raise ValueError("Recovery output must be outside the original run")
    campaign = source / "campaign" if (source / "campaign").is_dir() else source
    if not (campaign / "manifest.json").is_file():
        raise ValueError("Saved campaign manifest is required")
    inputs = {p.relative_to(source).as_posix(): sha256(p.read_bytes()).hexdigest()
              for p in sorted(source.rglob("*")) if p.is_file()}
    diagnostic = saved_campaign_diagnostics(campaign)
    output.mkdir(parents=True)
    (output / "diagnostics.json").write_text(json.dumps(diagnostic, indent=2, ensure_ascii=False) + "\n")
    (output / "input-seal.json").write_text(json.dumps(inputs, indent=2) + "\n")
    counts = diagnostic["persisted_runtime_status_counts"]
    report = ["# Диагностика сохраненного исследовательского прогона", "",
        "Это частичный операционный отчет. Метрики benchmark и повторная проверка Evidence не выполнялись.", "",
        f"Завершено вопросов: {diagnostic['questions_completed']}. Незавершено: {len(diagnostic['incomplete_questions'])}.",
        f"В завершенных вопросах: {diagnostic['model_calls_completed_questions']} обращений к модели, {diagnostic['actions_completed_questions']} действий.",
        f"Сохраненные runtime-статусы: {json.dumps(counts, ensure_ascii=False)}.",
        f"Групп подтвержденных протоколов/обработчиков: {diagnostic['confirmed_protocol_handler_group_count']}.",
        "Группа протокола/обработчика не является автоматически одной уникальной уязвимостью; повторные подтверждения нельзя считать независимыми.", "",
        "## Почему случаи остались без подтверждения", ""]
    report.extend(f"- {reason}: {count}" for reason, count in diagnostic["pending_reason_counts"].items())
    report.extend(["", "Каждый случай и повторные чтения перечислены в diagnostics.json.", "",
        "Старый прогон прерван вручную. Последний успешный ответ записан; сами логи не доказывают зависание последующего запроса.",
        "Бюджет кампании начинается после подготовки/SAST. По времени процесса нельзя определять момент истечения бюджета кампании.",
        "Латентности попыток включают время исправления схемы: простое суммирование строк лога завышает затраты.", ""])
    (output / "report.md").write_text("\n".join(report))
    if any(not (source / name).is_file() or sha256((source / name).read_bytes()).hexdigest() != digest
           for name, digest in inputs.items()):
        raise RuntimeError("Saved inputs changed during diagnostics")
    (output / "seal.json").write_text(json.dumps({p.name: sha256(p.read_bytes()).hexdigest()
        for p in output.iterdir() if p.is_file()}, indent=2) + "\n")
    return diagnostic


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = recover(args.source, args.output)
    print(json.dumps({"questions_completed": result["questions_completed"],
        "confirmed_protocol_handler_groups": result["confirmed_protocol_handler_group_count"]}))
