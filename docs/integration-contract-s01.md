# S01. Контракт интеграции поиска, проверки и исправлений

Версия документа: 1.0, 11.10.2026. База реализации: `22aab5d`.
Владелец: Ставр. Проверяющие: Кирилл (интеграция), Рома (Evidence и политика).
Статус: подготовлено к командному ревью; согласование людьми еще не проведено.

Это договоренность об интерфейсах, а не заявление о завершении будущих задач.
Канонические модели находятся в `schemas/`; новые локальные копии запрещены.
Примеры в `contracts/examples/s01/` синтетические, не результаты Juice Shop.

## 1. Граница этой задачи

S01 фиксирует существующие модели, связи, статусы, версии, ошибки и обязанности
потребителей. Меняет только проверки согласованности ID и чтение отчета через API.
Не расширяет сканирование, не добавляет capabilities, задания исправлений, новый
scoring, benchmark или автоматическую публикацию патча. Эти изменения принадлежат
S02–S11 и K/R-задачам ниже. Смена модели NSU выполнена отдельно по запросу пользователя.

Неизменная цепочка:

```text
Поиск -> Finding -> scoring / reasoning -> ActionProposal -> Validator
  -> Executor -> Evidence -> переоценка -> FinalReport -> Gate
confirmed + Evidence -> PatchReviewArtifact -> FixVerificationService
  -> отдельный snapshot -> Validator / Executor -> BEFORE / AFTER -> fix artifact
```

Модель предлагает, но не выдает разрешение. План, patch review, discovery и запись
в UI не разрешают исполнение. Generic argv возможен только через зарегистрированный
`sandbox_command`, в disposable Docker, без сети и с `/target` read-only.
Fix выполняется через `fix_target_stage` с операторскими adapter/stage ID.
Патч никогда не меняет исходный репозиторий, исходный отчет или исходный Gate.

## 2. Аудит моделей и потребителей

| Канонический контракт | Что уже передается | Производитель -> потребители |
|---|---|---|
| `Finding` (`finding.py`) | ID, источник, правило, файл/строки, severity, service, PR | SAST/Scout -> pipeline, graph, scoring, reporting |
| `ArchitectureContext`, `CVSSResult`, `ContextPriority` | факты архитектуры; раздельные оценки и обоснования | discovery/scoring -> reasoning, report, evaluator, UI |
| `AgentState` (`state.py`) | контекст, гипотеза, планы, решения, Evidence, бюджеты | graph/nodes -> reasoning, reporting; без SDK/runtime handles |
| `DynamicPlan`, `ActionProposal` | ID, tool, target/environment, параметры, ожидание | reasoning/planning -> Validator, approval store, Executor |
| `ValidationResult` | approved, action_id, причина, правила | Validator -> graph, approvals, Executor, report |
| `ExecutionResult` | run/action ID, статус, stdout/stderr, exit, timeout, evidence/audit ref | Executor -> evidence store/collector, graph, fix service |
| `Evidence` (`evidence.py`) | action, наблюдение, scope, refs, provenance, reliability, verdict | collector -> guard, reasoning, report, API, fix service |
| `FinalReport`, `ReportFinding` | finding projection, verdict, scoring, verification, история | builder -> API/store, rendering/UI, evaluator, patch review |
| `GateResult` (`pipeline.py`) | решение CI, код выхода, counts, errors, ссылки на finding | pipeline -> CI, API, evaluator; API убирает локальные report paths |
| `ProposedPatch`, `PatchReviewArtifact` | finding/run/file, diff, source/proposal hash, policy, окно правки | patch proposal/review -> fix service/workspace, demo API |
| `FixVerificationArtifact`, `FixStageResult` | BEFORE/AFTER, стадии, hashes, изоляция, cleanup, итог | fix service -> Stage 1/2 runner, evaluator; не исходный Gate |
| `ApiRun`, `ApiFinding`, `ApiEvidence`, progress DTO | жизненный цикл запуска и публичные проекции | orchestrator/SQLite -> API/UI |
| `TargetProfile`, `SourceMap` | операторские permissions/bindings; обнаруженные маршруты | registry/discovery -> pipeline, Validator, Executor, Scout |

`ReportFinding` и `ApiFinding` являются намеренными проекциями, не вторыми моделями
сканера. `FixCheck.argv` в старой модели не является новой capability исполнения.
Отсутствующие данные остаются отсутствующими: severity сканера не становится CVSS,
а неизвестная Context Priority не должна превращаться в ноль или low молча.

## 3. Идентификаторы и соединение данных

| Поле | Значение и правило |
|---|---|
| API `run_id` | ID запуска анализа; выдает orchestrator, не модель |
| `Finding.id` | ID кандидата; `FinalReport.finding_id == finding.id` |
| `rule_id`, `source` | происхождение кандидата, не ID известной уязвимости benchmark |
| `ActionProposal.id` | ID конкретной попытки; новая попытка получает новый ID |
| `ValidationResult.action_id`, `ExecutionResult.action_id`, `Evidence.action_id` | ссылка на ту же попытку; approval привязан к digest всего ActionProposal |
| `ExecutionResult.run_id`, `Evidence.action.run_id` | ID исполнения capability, не обязательно ID верхнего API запуска |
| `Evidence.id`, `hypothesis_id`, `sandbox_session_id` | ID доказательства, гипотезы и disposable сессии; не взаимозаменяемы |
| `PatchReviewArtifact.run_id`, `finding_id`, `proposal.finding_id` | review принадлежит одному analysis run и одной finding; finding ID обязаны совпадать |
| fix `id`, `workspace_id` | независимые ID проверки исправления и snapshot |
| benchmark `case_id` | независимый эталонный ID; соединение через явную разметку, не title/file line |

S01 проверяет внутреннее совпадение ID отчета и review при десериализации.
API дополнительно сверяет ID прочитанного отчета с запрошенным finding ID.
При несовпадении отказ, а не отдача чужого отчета. Проверки не заменяют проверку
run/file/source/proposal binding в `check_review` перед применением.
`model_copy(update=...)` не валидирует данные: после него перед границей доверия
нужен `model_validate`/JSON roundtrip и операционная проверка связей.

Формула стабильного finding ID, нормализация путей, fingerprint и объединение
дублей пока НЕ реализованы заново: это S02. Нельзя сейчас соединять разные версии
исходников исключительно по `file:line`, ни выдавать исторический ID за fingerprint.

## 4. Версии исходников и артефактов

`schema_version="1.0"` описывает формат, а не версию исходного проекта.
`SourceMap.schema_version` имеет собственный формат `cft.express_source_map.v1`.
Неподдерживаемая версия должна отклоняться явно, без угадывания полей.

Уже существует в fix chain:

- `source_sha256`: точные байты файла, прочитанного для review;
- `proposal_sha256`: SHA-256 сериализации `ProposedPatch.model_dump_json()`;
- `patch_sha256`: digest diff; не подменять digest всей proposal;
- `original_commit`: Git HEAD, не доказательство чистоты worktree;
- `original_tree_sha256` и `original_file_sha256`: фактический snapshot до правки;
- `patched_file_sha256`, BEFORE/AFTER evidence hashes, `policy_sha256`;
- pinned image и source commit задаются операторским target profile.

Сервис замораживает входы, проверяет hashes, containment, editable window,
неизменность оригинала и cleanup. Нельзя передавать host path/URL от модели.
Смена байтов исходника после review требует нового review, не автоматического retry.
Не менять алгоритм сериализации hashes в S01: это обесценит сохраненные reviews.

Пробел: общий Finding/FinalReport пока не содержит полного source-version binding.
S02 вводит в `schemas/` единый optional provenance-блок (commit, tree/file digest,
нормализованный путь, fingerprint, список исходных scan IDs), затем обновляет
нормализатор, builder, API/store и evaluator вместе. S03 добавляет типизированный
verification binding к source anchor, service, capability и версии policy.
Названия полей финализируются отдельным PR; отсутствие provenance означает
`unknown`, не разрешение перепроверить произвольный текущий исходник.

## 5. Статусы: не смешивать разные уровни

| Уровень | Допустимые состояния / смысл |
|---|---|
| finding report | `confirmed`, `rejected`, `inconclusive`, `policy_blocked` |
| graph | также промежуточные `continue`, `budget_ok`; не публиковать как verdict |
| action execution | `completed`, `failed`, `denied`; completed не означает confirmed |
| API run | `queued`, `running`, `cancelling`, `cancelled`, `completed`, `technical_failure` |
| patch review | `ready_for_review`, `rejected`; оба имеют applied=false/security_verified=false |
| fix result | `FIXED`, `NOT_FIXED`, `REGRESSION`, `INCONCLUSIVE`, `REJECTED` |
| fix verdict | `verified`, `not_verified`, `inconclusive`; не finding verdict |
| fix stage | `passed`, `failed`, `error`, `timed_out` |
| CI Gate | pass/warn/fail; exit 0/1/2 соответственно принятому техническому результату |

CI exit 1 = завершенный анализ с security/policy failure; exit 2 = техническая
ошибка. API `completed` возможен при exit 1. Отмена имеет собственный lifecycle
и может использовать exit 130, не расширяет enum кода Gate.
В pipeline summary статус `error` допустим для сбоя finding workflow, но не
должен записываться в `FinalReport.status`. Старые API Finding записи со строковым
статусом сохраняют совместимость; UI должен показывать неизвестный статус явно.

`confirmed` требует подходящего Evidence через guard, не текста модели.
Статическая проверка USER в Dockerfile подтверждает исходное условие, не runtime UID.
`rejected` требует опровержения, а отсутствие результата означает inconclusive.
Policy denial не является rejected или ложноположительной находкой.

`FIXED` требует BEFORE confirmed, AFTER явно rejected, успешных обязательных
build/tests/start/smoke, persisted execution/audit Evidence, совпадения binding,
сохранности оригинала и cleanup. Timeout, пустой AFTER или потеря artifact не FIXED.
Экспертные критерии достаточности/REGRESSION уточняет R03/R06, не LLM самостоятельно.

## 6. Ошибки, владелец и восстановление

Канонический `ErrorDetail`: code, layer, redacted message, retryable.
Не дублировать его свободной строкой в новом DTO. Текущие layers:
sast/agent/llm/validator/executor/storage/pipeline.

| Категория | Ответственный | Поведение |
|---|---|---|
| AUTH_ERROR, RATE_LIMITED, INVALID_RESPONSE (llm) | Ставр | разрешенный fallback; не бесконечный retry и не выдуманный результат |
| VALIDATION_ERROR, ISOLATION_BLOCKED | Рома + Кирилл | отказ до исполнения; scope не расширяется |
| TIMEOUT, EXECUTION_FAILED, BUILD_FAILED, DEPENDENCY_UNAVAILABLE | Кирилл | ограниченное восстановление; проверка без доказательств остается inconclusive |
| PERSISTENCE_ERROR (storage) | Кирилл | не заявлять verified без сохраненных артефактов |
| NOT_FOUND, UNSUPPORTED_RUNTIME | владелец вызываемого компонента | явная причина, не скрытый переход на другой target |
| INTERNAL_ERROR | владелец layer | диагностика; technical failure если workflow не завершился |

`retryable=true` не дает разрешения на повтор: действуют общие бюджеты, policy,
идемпотентность и новые action IDs. Пользовательский message не содержит токенов,
локальных абсолютных путей или полного stack trace. Диагностика остается в
ограниченных локальных артефактах. Старые `GateResult.stage_errors` уже преобразуются
в структурированные errors с redaction; эту миграцию сохраняем.

## 7. События, время и будущие задания

Существующие progress DTO обслуживают analysis run. Они не являются журналом
исправления и не доказывают воспроизводимость. K07 реализует отдельные задания
исправлений и получение артефактов; K08 добавляет временные события.

Требования для их будущего общего контракта в `schemas/`:

- разные analysis run ID / fix job ID / execution action ID;
- UTC timestamp с timezone, sequence/event ID, тип события, stage и attempt;
- lifecycle job отдельно от finding/fix verdict;
- ссылки на исходный run, finding, source version и patch review;
- публичный error = ErrorDetail; пути на хосте не выходят в API;
- события started/finished/error/cancelled; повторная доставка идемпотентна;
- cancellation не превращает частичный результат в FIXED;
- persisted timeline отделена от текстовых сообщений LLM.

MTTR считается по согласованным началу/концу (R02/K08), только для доказанно
исправленных случаев; длительность generation/replay не выдавать за производственный
MTTR. Уже имеющиеся started_at/finished_at/duration_ms fix artifact полезны, но
не закрывают сами по себе lifecycle обнаружения и доставки исправления.

## 8. Совместимость и примеры

Старые корректные v1 отчеты без agent_decisions, sandbox_actions, scoring,
stop_reason и явного schema_version читаются через defaults. S01 не вводит новых
обязательных полей и не меняет JSON форму. Неконсистентные ID теперь отвергаются;
это поврежденный контракт, не поддерживаемая историческая версия.
Архивы не переписываются. Для будущих обязательных изменений нужна новая версия
и явный reader/migration, включая API/store/UI/evaluator.

Машиночитаемые примеры:

- `finding.json`: кандидат поиска, не доказанная уязвимость;
- `report-v1-minimal.json`: старый минимальный inconclusive отчет;
- `patch-review-v1.json`: синтетический review, который ничего не применил;
- `fix-v1-minimal.json`: старый незавершенный результат исправления;
- `gate-v1-legacy.json`: технический сбой в старом stage_errors формате.

Их проверяет `tests/test_s01_contracts.py`: roundtrip, actual API report reader,
report renderer, негативные ID/версии, legacy Gate redaction, graph builder и
fix-chain serialization. Примеры не следует использовать как approved input
реального Executor или доказательство security_verified.

## 9. Что команда может делать дальше

| Задача / владелец | Обязательство перед общими контрактами |
|---|---|
| S02 / Ставр | нормализация, provenance, fingerprint, duplicates; совместимые проекции |
| S03 / Ставр + K03 / Кирилл | типизированный source/runtime binding вместо file:line fallback |
| R03 / Рома | критерии Evidence для capability, verdict и отказов |
| K06 / Кирилл, S08–S09 / Ставр | snapshot adapters и patch proposal только по этим binding/guards |
| K07 / Кирилл | job API, SQLite migrations, lifecycle, безопасные ссылки |
| K08 / Кирилл | persisted events/timestamps для fix time и доставки патча |
| S10 / Ставр | UI не смешивает execution/run/verification/fix status |
| R01/R02 + evaluator / Рома/Кирилл | независимый case_id, фиксированная версия и явные неизвестные данные |

Изменение общей схемы: перечислить producer/consumer, добавить пример старого
и нового JSON, serialization/negative tests, обновить API/schema/migration/UI
в том же PR либо явно отделить совместимую подготовку. Кирилл проверяет интеграцию,
Рома проверяет Evidence/policy. Их настоящее ревью остается необходимым.

## 10. Проверка реализации S01

11.10.2026: полный pytest — 514 passed, 18 skipped. Пропуски: Docker sandbox,
multi-run и SberLab интеграции без рабочего daemon/pinned image; opt-in Stage 1
и Stage 2 без подготовленного pinned checkout. Их прохождение не заявляется.
19 новых контрактных тестов включены в полный набор. `python -m app.main`
завершил детерминированный demo с confirmed и одним Evidence.
Ruff прошел для всех tracked Python файлов и нового теста. Общий `ruff check .`
обнаруживает прежние ошибки в посторонних untracked `tmp/pdfs` и `ultra-os`;
эти файлы не изменялись и в PR не входят.

NSU: новый ключ проверен GET models и живым completion через адаптер проекта.
Маршрут по умолчанию: `nsu:qwen3.8-flash-next`, резерв `nsu:Qwen3.8-27B`.
Два одинаковых коротких JSON-запроса на модель с temperature 0.1, max_tokens 256,
reasoning_effort xhigh: Flash 0.69/0.42 с, 27B 0.51/0.54 с. Все ответы валидные;
этого недостаточно для вывода о качестве reasoning или преимуществе по скорости
на полном workflow. Smoke через `ProviderFailoverClient` и `LLMProbeResult`
завершился за 0.61 с. Это не benchmark безопасности.

Ключ остается только в ignored `.env`. У процесса инструмента обнаружен старый
`NSU_OPENWEBUI_KEY` во внешнем окружении, который имеет приоритет над dotenv.
Smoke проверен без этого переопределения. При запуске проекта используйте свежий
процесс с актуальным окружением (либо `env -u NSU_OPENWEBUI_KEY ...` для чтения
ключа из `.env`). Уже работающие сервисы сами конфигурацию не перечитывают.
Режим по умолчанию оставлен `stub`; живой запуск выбирает `llm` явно.
