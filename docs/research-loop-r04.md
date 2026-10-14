# R04: исследовательский цикл

## Что реализовано

Новый opt-in режим использует **существующий LangGraph**, а не параллельный
исполнитель. `ResearchAgentModel` реализует `AgentReasoningModel` и использует
существующий `ProviderFailoverClient`. Один структурированный ответ модели
содержит анализ, гипотезу и ровно одно следующее действие либо честную остановку.
`analyse`, `form_hypothesis` и `build_plan` не делают три отдельных API-запроса.
Живой клиент принимает только один явно выбранный маршрут, без скрытого failover
и повторных запросов в рамках одной итерации.

Путь каждого действия:

```text
модель выбирает следующий эксперимент
→ приложение добавляет target/session/binding/action_id
→ DynamicPlanValidator
→ PolicyValidator с замороженным операторским scope
→ SafeExecutor и Docker
→ сохраненная execution-запись + отдельный matching audit
→ Evidence/research ledger
→ модель получает наблюдение и выбирает новый шаг
```

Отсутствие зарегистрированной специализированной проверки больше не завершает
**исследовательский** режим: доступны чтение и буквальный поиск исходников,
запись/чтение рабочей области, Python/Node-скрипты и операторский `target_http`.
Обычный старый режим и его B01/B05/B06 разрешения не расширены.
HTTP требует отдельный доверенный registry/internal network. Скрипты остаются
без сети; target, URL, роли и права нельзя добавлять ответом модели.

## Память и ограничения

В `AgentState` попадают только сериализуемые `research_scope` и
`research_progress`, не runtime, SDK, broker или секреты. Ledger хранит
наблюдения, provenance, ссылки на execution/Evidence/audit, код завершения,
категорию ошибки и fingerprint. Интерпретации модели хранятся отдельно как turns.
Ссылка на несуществующее наблюдение отклоняется.

`ResearchLimits` ограничивает действия, вызовы модели, wall time, размер контекста,
суммарный резерв model IO, объем наблюдений и записанного кода. Runtime отдельно
ограничивает HTTP, объем tmpfs, процессы и время действия. Model IO считается
**по резерву байтов**, включая схему и резерв ответа; это не точный учет токенов
провайдера и не финансовая квота. Wall deadline кооперативный, с ограниченными
таймаутами и обязательной уборкой, не мгновенное принудительное завершение.

Контекст не копирует всю историю планов/скриптов. Он включает индекс всех
наблюдений и помещающиеся свежие результаты; обрезка последнего явно помечается
и сохраняет digest полной записи. Полный ledger остается в артефактах.

Повтор неизмененного source/HTTP действия останавливается. Новый action id или
описание не обходят fingerprint. Workspace read может повторяться после записи
или эксперимента; тот же script не создает себе новую версию простым повтором.
Проверка консервативна: не доказывает, что две разные программы семантически
эквивалентны. Общий step budget остается последней границей.

Неудачный скрипт с достоверным наблюдением передается следующей итерации, а не
считается техническим падением пайплайна. Ошибки исполнения сохраняются в
action history. Потеря audit, отказ Validator/Executor, нарушение scope и
runtime failure без наблюдения не обходятся новой попыткой модели.

## Как запускать

```bash
python -m app.research_run \
  --profile targets/juice-verification.yaml \
  --checkout /absolute/pinned/juice-shop \
  --operator-config /absolute/research-config.json \
  --finding /absolute/finding.json \
  --output artifacts/r04-new-run
```

`finding.json` соответствует каноническому `Finding`; каталог output новый.
Конфигурация оператора минимально содержит `worker_image` (immutable image ID
либо repository digest) и `source_files` (допустимые исходники). Без списка
берется `git ls-files`, затем применяется существующий фильтр исходников.
Образ должен содержать фиксированный worker, Python и Node; сборка описана в
`executor/research.Dockerfile` и отчете R00–R03. Не передавать mutable tag.

Для HTTP используются `runtime_service_map` и `http_grants`, либо явные
`services`/`network_name` оператора. Режим CLI анонимный: приватные role credentials
не принимаются в JSON/AgentState; их provisioning относится к runtime API.
`--limits` принимает JSON `ResearchLimits`. Для LLM установить локальную
конфигурацию одного действующего маршрута `CFT_LLM_ROUTES` и секрет вне Git.
Клиент общий с существующим агентом; новый ключ в этом этапе не устанавливался.

Выход: `report.json`, `progress.json`, `events.jsonl`, `summary.json`, execution
файлы, audit, scope и lifecycle cleanup. Checkpoint — диагностический снимок,
**не обещание resume**: approvals и удаленная рабочая область не восстанавливаются
по JSON автоматически. `summary.json` появляется после успешной уборки.

## Что это пока НЕ дает

R04 сам не создает новую scanner/surface очередь — это R05. Независимые протоколы
подтверждения — R06. Поэтому результаты этих инструментов и остановка
`research_complete` дают `inconclusive`, не `confirmed`/`rejected`. Нельзя
отчитываться ими как измеренным ростом Recall или новым Juice Shop benchmark.

## Проверка реализации

```bash
python -m app.research_loop_acceptance \
  --image sha256:<installed-research-image-id> \
  --output artifacts/r04-new-acceptance
python -m app.research_loop_verify \
  --image sha256:<installed-research-image-id> \
  --output artifacts/r04-new-verification
```

Acceptance использует **тестовую модель**, настоящие Docker/graph/Validator/
Executor и сохраненные результаты. Она реагирует на предыдущий stdout/digest,
меняет скрипт после ошибки и читает созданный файл. Отдельно проверяются повтор,
step/call budgets и выдуманная ссылка. Это не живой LLM и не тест качества поиска.
Target для проверки — синтетический marker, намеренные уязвимости не добавляются.
Используется профиль с существующими verification routes, чтобы отсутствие
специализированной проверки не блокировало исследовательский режим.

Структурированная редактировка исправляет найденный дефект R00–R03: форматтер
ошибок обрезал JSON при traceback внутри stderr. Теперь redaction применяется
после разбора JSON к отдельным значениям, сохраняя envelope и причину ошибки.

Публикуемые результаты:
`artifacts/r04-loop-acceptance-2026-10-15-final-v2/`,
`artifacts/r04-loop-verification-2026-10-15/`,
`artifacts/r04-foundation-regression-2026-10-15/`,
`artifacts/handoffs/research-loop-r04-2026-10-15.zip` и `.sha256`.
Каждая директория содержит `seal.json`, ZIP содержит SHA256 manifest и
source-provenance с Git ref кода. Это portable diagnostic handoff, не A/B metrics.

Зафиксированная проверка 15 октября 2026: полная suite **1232 passed, 19 skipped**;
отдельный файл R04 с включенным Docker **17 passed** (включая интеграцию).
Ruff и прежний `python -m app.main` прошли. R04 Docker acceptance: **11/11 PASS**,
шесть действий адаптивного сценария и семь запросов к тестовой модели.
Причины пропусков перечислены в `unit-suite.log`: внешние SberLab/Autodealer,
исторические opt-in Docker/fix/demo prerequisites. Пропущенная в общей suite
R04 Docker проверка отдельно выполнена. Живой NSU/LLM и качество поиска на
Juice Shop в этом этапе не измерялись.
Повторная проверка прежних инструментов R00–R03: **30/30 PASS**, включая
изоляцию, read-only source, выход в сеть, процессы, HTTP scope и cleanup.
