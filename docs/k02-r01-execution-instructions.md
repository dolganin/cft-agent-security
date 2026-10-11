# Инструкция выполнения K02 и R01

Дата: 11 октября 2026. Рабочая ветка: `codex/s01-integration-contracts`.
Это инструкция для реальной разработки, а не описание уже выполненных задач.
`main` не менять. Закрытие задач допускается только по проверенным артефактам.

## 1. Разделение работы

Два независимых исполнителя:

- K02: воспроизведение baseline, трассировка потерь, журнал причин.
- R01: спецификации проверок, критерии Evidence, шаблон разметки.

Модель обоих: `gpt-6-luna`, reasoning `high`. Основной агент проверяет
результаты, совместимость и итоговые тесты. Субагенты не создают новых
субагентов, не делают commit/push/merge и не меняют рабочую ветку.

Перед работой полностью прочитать `AGENTS.md` и соответствующие разделы
`docs/agent-team-tasks-2026-10-10.md`. Документы плана пока являются локальными
неотслеживаемыми файлами: не удалять и не переписывать их.

Не откатывать чужие изменения. Использовать `apply_patch` для редактирования.
Не включать `.env`, ключи, bytecode, зависимости и target checkout в коммит.
Python запускать с `PYTHONDONTWRITEBYTECODE=1`.

## 2. Обязательные границы

Агент предлагает, Validator разрешает, Executor выполняет, Evidence определяет
результат. Не ослаблять проверку разрешений, изоляцию Docker, scope, бюджеты
или критерии confirmed ради успешного опыта.

Цель только локальная тестовая Juice Shop. Никаких внешних атак, произвольных
адресов или выполнения кода цели на хосте. Зависимости цели и ее скрипты
запускаются только в Docker. Не останавливать посторонние контейнеры, не
использовать Docker prune, не удалять существующие артефакты.

API-ключ брать из существующего локального конфига. Значение не выводить,
не сохранять в логах и не передавать в аргументах команд. В процессе может
быть устаревший `NSU_OPENWEBUI_KEY`: для чтения актуального `.env` допустим
`env -u NSU_OPENWEBUI_KEY`. Отказ модели записать как отказ, не заменять
результат детерминированной заглушкой под видом LLM.

## 3. K02: область владения

Разрешены собственные новые файлы `evaluation/baseline_diagnostics.py`,
`app/baseline_diagnostics.py`, `tests/test_baseline_diagnostics.py`,
`docs/k02-baseline-diagnostics.md` и новые каталоги
`artifacts/k02-2026-10-11-*`. Если выбран другой набор файлов, сначала сообщить
основному агенту. Общие schemas, policy и runtime не менять без согласования.

### 3.1. Зафиксировать начальные условия

1. Снять branch/HEAD, статус tracked исходников, версии Python, Docker,
   Semgrep, наличие необходимых образов и target checkout.
2. Сверить точный target commit:
   `5658473cf8814459bf89000ce373b20ed0b4eb37` (Juice Shop v20.2.0).
3. Использовать отдельную чистую LF-копию для Stage1 и отдельную копию для
   benchmark; не изменять presentation checkout или старые результаты.
4. Прочитать `benchmarks/juice-shop-v20.2.0/README.md`, `benchmark.yaml`,
   `dataset.lock.json`, инструкции Stage1 в `docs/demo/README.md`.
5. Зафиксировать конфигурацию до запуска: хеши YAML, source bytes, реальные
   image IDs/RepoDigests, маршруты моделей без ключей, бюджеты, command argv.
6. Каталог попытки и ее ID должны существовать ДО preflight. В текущем
   `app.stage1_e2e` preflight может завершиться до создания run directory;
   диагностический wrapper должен сохранить такой отказ отдельно.

Сейчас Docker доступен, образ Juice Shop v20.2.0 присутствует; стандартные
`artifacts/stage1-juice-shop` и `artifacts/benchmark-target/juice-shop`
отсутствуют, fix image и Python worker image не обнаружены при инвентаризации.
Это наблюдения начала работы, не гарантии текущего состояния.

### 3.2. Реально повторить два контура

1. Под «v1» понимать dataset `juice-shop-v20.2.0-v1` из Stage2, а не
   произвольный ранний демо-набор. Запускать существующий официальный harness.
2. Попытка v1: один новый запуск `app.stage2_benchmark --runs 1` с новым
   output и фиксированной конфигурацией. Не выдавать его за исторические
   три запуска и не приписывать ему полный recall всего проекта.
3. Попытка Stage1: существующий `app.stage1_e2e` с новым output, реальными
   worker/fix images и чистым target. Сохранить BEFORE/AFTER, review,
   fix-verification, original-before/after, execution, audit и cleanup.
4. Provisioning проводить отдельно от измеряемого опыта. Локально собранный
   образ без RepoDigests сейчас может не пройти pinning: зафиксировать
   конкретную ошибку; не подделывать digest и не разрешать mutable tag.
   Перед изменением общего runtime передать воспроизводимый пример основному
   агенту. Этот prerequisite относится к K01.
5. При отсутствии предпосылок сохранять BLOCKED/PREFLIGHT_FAILED, exit code,
   длительность и redacted ошибку. Это не полноценный scored run.
6. Любое изменение настройки требует нового experiment ID. Старый каталог
   не перезаписывать и не дописывать результаты нового опыта в старый seal.

### 3.3. Найти точные места потерь

Для SQL и file/directory cases построить таблицу:

`raw finding → normalized finding → source/endpoint binding → ActionProposal
→ ValidationResult → ExecutionResult → persisted Evidence → FinalReport`.

Для каждой ступени сохранить finding/alias/action/session/run ID и ссылку на
конкретный файл. Отсутствующую ступень обозначать missing, а не додумывать.
При нормализации различать дедупликацию и потерю; provenance S02 хранит
наблюдения и aliases. Статическое confirmed не равно runtime exploit proof.

Категории причины: source path, source version, binding, permission, runtime,
model, timeout, Evidence schema/interpretation, unresolved. Не определять
причину только по тексту итоговой ошибки, если доступны более ранние данные.

Отдельно проверить известный факт: четыре старых отчета
`artifacts/security-pipeline/reports/*.json` несовместимы с текущей Evidence
schema. Нельзя «мигрировать» их путем придумывания approval, action или
session. Это архивная несовместимость, не доказательство нового падения.

### 3.4. Диагностический инструмент и тесты

Сделать небольшой read-only CLI для воспроизводимой диагностики, если
существующие инструменты не дают указанной цепочки. Не переписывать pipeline.
Входы оператора: каталог artifacts и явно выбранный target, без credential.
Выход: структурированный журнал с ID, стадией, категорией, доказательством
и статусом explained/unresolved. Не считать failed preflight метрикой агента.

Тесты: валидная цепочка; потеря binding; deny; timeout; malformed Evidence;
неизвестная причина; alias после дедупликации; отсутствующий файл; попытка
повторно использовать каталог; секретоподобный текст в ошибке редактируется.
Синтетические fixtures обозначать как synthetic и не считать живым прогоном.

### 3.5. Результат K02

Документ: таблица попыток, конфигурации, наблюдаемые причины, минимальные
команды воспроизведения, ссылки на артефакты, оставшиеся prerequisites.
Stage1 operator SQL patch проверяет verifier, НЕ генерацию исправления LLM.
K02 не отмечать полностью закрытой, пока реальные v1 и Stage1 не повторены.
Если удалось только preflight, честно выдать частичный результат и blocker.

## 4. R01: область владения

Разрешены новые `docs/r01-verification-specifications.md`,
`contracts/examples/r01/` и `tests/test_r01_specifications.py`.
Production schemas, allowlists и interpreter без согласования не менять.
Новые capabilities в этой задаче являются СПЕЦИФИКАЦИЯМИ, не доступными tools.

### 4.1. Пять спецификаций

Для ownership read, ownership write, authentication/authorization bypass,
redirect и безопасной code-injection verification описать каждое поле:

- утверждение, которое проверяется, и точный ограниченный scope;
- операторский endpoint/service ID, роли A/B, принадлежность объектов,
  исходный snapshot/reset, отсутствие доступа к production;
- разрешенные параметры по ID, бюджеты запросов/ответов/времени;
- положительный контроль доступности и прав, отрицательный контроль защиты;
- проверочное действие и повтор наблюдения на новом/сброшенном состоянии;
- достаточные факты confirmed и rejected;
- inconclusive при lost session, unknown owner, truncated response,
  technical error, несовпадении binding или недоступном контроле;
- cleanup и подтверждение отсутствия побочных изменений;
- пример позитивного и негативного теста, а также неопределенного результата.

Ownership read: доказательство доступа A к операторскому объекту B при
подтвержденной принадлежности и отсутствии разрешения, не просто HTTP200.
Ownership write: независимый readback изменения объекта B, отсутствие
законного права и успешный reset; не статус ответа на запись.
Auth: различать authentication и authorization, проверять фактическую
защищенную операцию/личность, а не наличие token-подобной строки.
Redirect: проверять Location без перехода на внешний сайт, использовать
операторский безопасный sink; разрешенный redirect не является дефектом.
Code injection: только ограниченный безвредный marker/вычисление в
одноразовом контейнере, без shell, файловых изменений, сети или секретов.
Текстовое отражение marker не равно исполнению. Не включать произвольные
эксплуатационные payloads или новую execution capability в этот этап.

### 4.2. Совместимость с Evidence

Использовать существующие `Evidence`, `EvidenceAction`, `EvidenceObservation`,
`EvidenceScope`, `EvidenceArtifact`: указать mapping для каждого сценария.
Action ID совпадает с одобренным действием; execution и audit проверяемы;
runtime Evidence требует sandbox_session_id; source version и endpoint
binding должны соответствовать опыту. Секреты и реальные пользовательские
данные в facts/logs не сохранять.

Source map только помогает найти кандидат. Она не выдает разрешение и не
расширяет target/endpoint/role allowlists. Отсутствие подтверждения не значит
rejected; отказ Validator означает policy_blocked в workflow, не «безопасно».

### 4.3. Каталог и рубрики для Лехи

Подготовить машиночитаемый TEMPLATE, не утвержденный ground truth:
case ID, pinned version, family, service, source/HTTP anchors, root cause,
предполагаемый verdict, позитивные/негативные контроли, prereqs, scope,
required facts, источники, severity/CVSS applicability, Context Priority,
unknown reason, reviewer/status, eligible fix и основание eligibility.

Не выводить severity из Semgrep ERROR/WARNING или CTF звездочек.
CVSS численно вычисляется детерминированно по явным метрикам; пока метрик
нет, использовать UNASSESSED/unknown. Context Priority отдельно, только
по известным архитектурным фактам с contribution/reasons и unknown.

Сверить источники с официальным OWASP WSTG и закрепленными исходниками
Juice Shop. URL источника и commit/anchor необходимы; названия challenge
не доказывают severity. Разметку full benchmark утверждают L01/R02,
эта задача ее не подменяет.

### 4.4. Проверка R01

Тесты должны проверять полноту всех пяти specs и валидность примеров текущим
Evidence model, включая позитивный, негативный и inconclusive пример.
Документация должна позволять написать будущий capability contract test без
угадывания роли, владельца, контроля, verdict semantics или очистки.
Fixtures явно synthetic, не новые находки и не результаты Juice Shop.

## 5. Передача результатов основному агенту

Каждый исполнитель возвращает: измененные файлы, команды тестов и результаты,
фактические live run ID, prerequisites/blockers, что осталось и почему.
Не называть задачу закрытой на основании только unit tests или документа.

Основной агент проверяет diff и артефакты, запускает полный pytest,
Ruff по tracked/new Python без стороннего `tmp`/`ultra-os`, deterministic
`python -m app.main`. Только после проверки можно сделать отдельный commit
в существующую ветку и обновить PR #8. Слияния с main в этом этапе нет.
