# B08: обоснованная серьезность и контекстный приоритет

Статус: программная реализация и детерминированная приемка завершены.
Ветка: `codex/b08-scoring`. Исторический A04 v2 не изменен.
Это не B09 и не новый замер качества поиска на Juice Shop.

## Три независимые оценки

| Результат | Основание | Что нельзя подставлять вместо него |
|---|---|---|
| CVSS 4.0/B | 11 явно обоснованных базовых метрик; `cvss==3.6` | Semgrep ERROR/WARNING, сложность задания, A04 HIGH |
| Source-impact severity | Отдельная рубрика `source-impact.a04.v1` | Числовой CVSS и его категории |
| Context Priority | Архитектурные факты; прежние веса v0.1 | Серьезность сканера и CVSS |

Калькулятор: https://github.com/RedHatProductSecurity/cvss.
Обоснованные нулевые impacts дают CVSS 0.0; неизвестные impacts дают UNASSESSED.
Docker USER hardening сохраняет прежнее N/A. Environmental/threat metrics пока
не поддерживаются. Числовые оценки не создают Evidence или runtime verdict.

Узкая ordinal рубрика HIGH включает: прямое раскрытие базы, обход аутентификации,
несанкционированное постоянное изменение и получение административной роли.
Это source-impact assessment, не автоматическая классификация всех уязвимостей
и не официальная severity Juice Shop. Без обоснованных фактов — UNASSESSED.

## Операторский ввод и рабочий контур

CLI поддерживает `--scoring-reviews <operator-reviews.json>` в `app.pipeline_run`.
Файл — JSON-массив объектов `schemas.scoring.ScoringReview`; его разобранная
копия сохраняется в output/scoring-reviews.json. API не принимает произвольные
пути к review. Без операторских reviews обычный workflow продолжает работу,
не придумывая метрики. Автоматический LLM extraction CVSS не включен.

Каждый review включает finding_id и `scoring.review.finding_review_digest(finding)`,
reviewed_by/rationale и references: ID, канонический относительный source file,
SHA256 всего файла, диапазон строк, рассмотренные metric/impact identifiers.
CVSSAssessmentInput и source-impact facts необязательны.

Пример формы review и finding находится в acceptance-пакете. Он синтетический:
его значения нельзя переносить на Juice Shop. Для CLI объект review требуется
обернуть в JSON-массив.

Проверяются привязка к находке, уникальность ссылок, пути внутри target root,
размер/UTF-8/хеш/диапазон исходника, пересечение с source anchor находки и
явная привязка каждой метрики/impact к рассмотренному reference. Команды из
review не выполняются. Ссылки не дают разрешений. Ссылки — на исходники;
приемка runtime Evidence/audit в качестве metric input пока не поддерживается.
Неподтвержденные runtime assumptions нельзя отмечать установленными source facts.

Review проходит через AgentState → score_finding → FinalReport. Перед отчетом
source binding проверяется повторно. Измененный исходник оставляет UNASSESSED
с диагностикой. Ошибка review не роняет workflow и не меняет доказательный
вердикт. Source-only находки тоже сохраняют оценки отдельно от inconclusive.

Граница доверия: хеш и binding проверяются кодом, семантическая истинность
source facts остается ответственностью оператора. reviewed_by не является
электронной подписью. Это не независимая аттестация runtime binary. Model output
не является источником operator reviews или доверенных ссылок.

## Неизвестный контекст

ArchitectureContext сохраняет unknown_inputs при JSON roundtrip. Адаптер не
превращает отсутствующий exposure/connectivity в явно отрицательные факты;
явные overrides снимают неопределенность соответствующих полей. Неизвестные
категории также помечаются. Старые вклады/пороги v0.1 сохранены; неполный score
обозначен partial. CI Gate не переписан: он может консервативно использовать
имеющийся уровень CP; partial запрещает выдавать его за полную оценку риска.

JSON, текстовый отчет и раскрытая карточка находки показывают статус/неизвестные
входы. Severity сканера подписана как не-CVSS. Промпт требует не останавливать
исследование из-за отсутствия CVSS/CP. Приемка сравнивает полный ActionProposal
и решения Validator с review и без него.

## Сопоставление с A04

`evaluation.scoring_b08.evaluate_scoring(dataset, reports, case_reports)` — отдельный
evaluator-only помощник. Сопоставления case ID → finding ID заранее проверяет
оценщик; это не новый автоматический matcher. Помощник проверяет существование,
уникальность и original source anchors, отказывает для patched/synthetic samples.
Неоднозначное совпадение требует отдельной adjudication; нельзя выбирать его
ради нужного score.

Сравниваются только совместимые схемы: ordinal A04 с source-impact assessment,
CP v0.1 с независимой CP разметкой, если она есть. Partial CP, отсутствующие
оценки и несоответствие схем не входят в assessed accuracy. Отдельно возвращаются
total/reviewed/assessed/correct, reviewed coverage, assessed coverage и accuracy.
CVSS accuracy относительно ordinal A04 всегда N/A.

В A04: 41 запись, 4 размеченных ordinal HIGH и 0 CP labels. CP accuracy сейчас
N/A, не 0% и не 100%. Для остальных severity не LOW, а N/A. Новая разметка
CP требует отдельной версии эталона и независимого review. В acceptance есть
проверка знаменателей с **нулем observations**: это проверка контракта, не новый
baseline и не оценка агента. Oracle не импортируется в production scoring,
reasoning или пайплайн.

## Приемка и воспроизведение

```bash
python -m pytest -q
python -m app.main
python -m evaluation.benchmark_freeze validate
python -m app.b08_acceptance run --output artifacts/b08-acceptance-new
python -m app.b08_acceptance replay --input artifacts/b08-acceptance-new
python -m app.b08_acceptance package --input artifacts/b08-acceptance-new --output artifacts/b08-handoff-new.zip
```

`run` использует два синтетических safe_noop workflow, без Docker target scripts,
LLM и SAST. Проверяет путь score → Validator/Executor → FinalReport, 9.9 reference
vector, независимость действий от scores, partial context, hash binding и отказ
при устаревшем источнике. Сохраняет source, review/finding, оба отчета, действия,
execution/audit и копии реализации. seal.json связывает SHA256 и точный состав
файлов. ZIP имеет SHA256 sidecar.

Для handoff распаковать архив в новую папку и дважды выполнить `replay` с ней
через соответствующий checkout проекта. Replay не запускает Executor/Docker/LLM.
Подмена файла вызывает отказ. Seal доказывает целостность относительно
опубликованного commit, а не внешнюю подпись автора.

Новые метрики качества/рост recall измеряются в B09. B05/B07 не требовались
для B08. Полная автоматизация CVSS/CP на всех находках не заявляется.

## Финальная проверка, 14 октября 2026

- Backend: **1098 passed, 18 skipped**, одна LangChain deprecation warning.
- Новых B08 backend тестов: 34; frontend: 29 passed, включая новый B08 тест.
- Ruff проекта (исключены посторонние tmp/ultra-os/output), production frontend
  build, `app.main` и `git diff --check` прошли.
- A04 preflight: valid_frozen_a04, 41 cases, 114 inputs bound. Target source
  повторно не проверялся; новых runtime cycles нет. Проверка исторического
  lock не означает независимую приемку текущего implementation.
- 18 skips: 1 A05 saved-artifact opt-in, 6 Docker boundary, 1 multi-run lifecycle,
  4 sandbox manager, 1 sandbox runner, 3 SberLab sessions, 1 Stage1 E2E opt-in,
  1 Stage2 pinned-checkout prerequisite. Они не выдаются за пройденные интеграции.

Переносимый пакет: `artifacts/b08-handoff-2026-10-14.zip` и `.zip.sha256`.
В нем содержатся source/review/report/control, audit, seal и снимки реализации;
полный pytest output — `docs/b08-validation-2026-10-14.txt`.
