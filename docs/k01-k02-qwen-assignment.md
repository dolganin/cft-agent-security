# K01 + завершение K02: задание NSU Qwen через OpenCode

Дата: 2026-10-11. Это эксперимент с coding worker, не смена модели самого агента.
Модель: `nsu/qwen3.8-flash-next`. Reasoning: `xhigh`. Живой сервер отклонил
`high` с HTTP 400 и перечислил поддерживаемые `xhigh`, `medium`, `low`.

## Репозиторий и публикация

- Workspace: `/Users/stavrmoris/Desktop/cft-security-agent`.
- Ветка: `codex/s01-integration-contracts`, HEAD на выдаче: `a6ca5db`.
- Remote: `https://github.com/Ultramind-AI/cft-security-agent.git`.
- Существующий открытый PR #8: эта ветка → `main`.
- Субагент НЕ делает git add/commit/push/pull/merge/rebase/checkout/reset.
  Он меняет разрешенные файлы и возвращает отчет. После независимой проверки
  основной агент делает явное staging нужных файлов, commit и push в
  `origin codex/s01-integration-contracts`, проверяет remote SHA и обновляет
  существующий PR. Создавать новую ветку/PR или пушить в main не нужно.

Не один в кодовой базе: не откатывай и не переписывай чужую работу.
Уже есть несохраненные в Git результаты K02 и R01, локальные планы,
измененные tracked `.pyc`, `tmp`, `output/pdf`, `ultra-os`. Не включать их
автоматически, не удалять и не «очищать» рабочее дерево.

## Перед изменениями

Полностью прочитай `AGENTS.md`, `docs/k02-r01-execution-instructions.md`,
разделы K01/K02 в `docs/agent-team-tasks-2026-10-10.md`,
`docs/k02-baseline-diagnostics.md`, текущие диагностические файлы и тесты,
Stage1 runtime/target contracts, `docs/demo/README.md`.

Нельзя обходить Validator, зарегистрированный Executor, Docker-изоляцию,
scope, Evidence или бюджеты ради положительного результата. Код целевого
Juice Shop запускать только внутри Docker. Не менять production доступ,
ключи, модель агента, LangGraph, scoring или security tools. Никакого prune,
удаления/остановки чужих контейнеров или перезаписи старых экспериментов.

## 1. Довести K02

### 1.1. Не потерять отказ запуска

В `evaluation/baseline_diagnostics.py::run_attempt_stage` сейчас
`subprocess.Popen` может выбросить OSError. Запись остается RUNNING и финальный
журнал не создается. Обработай missing executable, inaccessible cwd и другие
ошибки создания процесса: сохранить timestamp, duration, redacted error,
явный failed/preflight_failed статус, exit_code=null и отдельный признак
launch failure. CLI должен возвращать ненулевой код. Не маскировать это
timeout или security finding. После отказа не должно оставаться RUNNING.

Добавь regression tests для missing executable и missing cwd. Добавь
проверку stage identifier: только безопасное имя без `/`, `..`, separator
или absolute path, чтобы stdout/stderr не писались за attempt directory.
Проверь, что конфигурация попытки и вывод не сохраняют credential values.
Не создавай новый универсальный host executor: это операторский диагностический
wrapper существующих команд, не tool, доступный reasoning модели.

### 1.2. Проверить утверждения по артефактам

Существующий новый baseline:
`artifacts/k02-2026-10-11-stage2-5f6481c9/stage2-output/run-001`.
Проверены seal 47 файлов и 10 FinalReport. Detection TP/FP/FN/TN=5/0/5/2;
но confirmed только 4, verified recall=0.4. Не писать recall по confirmed=0.5.

Stage1:
`artifacts/k02-2026-10-11-stage1-cd97a2e4/stage1-output/stage1-a5b899ec304240b79fae53411adcb0ec`.
FIXED, BEFORE confirmed, AFTER rejected, 10 стадий, source unchanged, cleanup.
Это operator IntegrationPatchClient, не генерация патча моделью.

Сохрани отчеты/attempt/seal неизменными. Исправляй диагностический код и
документ, не историческую Evidence. Отсутствующая ActionProposal остается
честно missing/unresolved; ее сериализация отдельная задача интеграции,
не придумывай предложение задним числом.

## 2. Довести K01

### 2.1. Паспорт и жизненный цикл

Добавь `docs/k01-environment-passport.md`: версия ОС/архитектура, Python,
Docker, Semgrep, Node внутри image, agent commit + dirty source digest,
target commit и source bytes, фактические image IDs/RepoDigests, все настройки
и ограничения. Credentials не читать/печатать/копировать.

Опиши проверенные команды prepare/start/health/reset/stop, отдельные исходные
копии analysis/fix, префиксы собственных контейнеров/сетей, сохранение логов,
бюджеты и как убедиться, что отсутствуют leftovers. Только проверенная macOS;
Windows/Linux не объявлять поддержанными на основании unit tests.

Отдельно различать preflight инфраструктуры, нейтральный model probe и
startup приложения. Если neutral model test нужен, используй существующий
project adapter, а не вывод `.env`. Не отправляй benchmark truth модели.

### 2.2. Локальные образы без RepoDigests

Сейчас TargetFixConfig принимает только `repo@sha256:...`, а Stage1
`pinned_image` отвергает локальную сборку без RepoDigests. Наш текущий image
имеет RepoDigest, но это не решает общий K01 prerequisite.

Если нужно поддержать локальную сборку, допускай только полный immutable
Docker image ID `sha256:<64 lowercase hex>` после фактического image inspect.
Никаких mutable tags в runtime и выдуманных repo digest. Теги допустимы
только как operator provisioning input, сразу разрешаемый в immutable ref.
Проверь downstream consumers до shared schema изменения и сохрани все
security boundaries: --pull never, networkless build/tests, readonly source,
internal network runtime checks, budgets. Не рефакторь runtime без нужды.

Допустимая область: `app/stage1_e2e.py`, `schemas/target.py`, существующие
target/stage1 tests и новые `tests/test_k01_environment.py`. Другие общие
файлы не менять без объяснения необходимости в отчете.

Тесты: valid repo digest, valid full image ID, mutable tag denied runtime,
короткий/невалидный ID denied, missing image не вызывает pull,
локальный image без RepoDigests разрешается в настоящий immutable ID.
Не требовать registry push как обязательное условие локального запуска.

### 2.3. Реальная повторная проверка

Два независимых Stage1 цикла с подготовленным pinned target, разными output
каталогами/run/session ID. Если уже есть пригодный первый цикл K02, засчитывай
его как первый только после проверки исходных manifests/images; второй
делай новым. Сравни frozen config/source/image IDs; проверь BEFORE/AFTER,
health/stages, original integrity и cleanup. Запиши точные IDs и длительность.

Для target reset докажи, что после teardown и нового startup исходное
состояние восстановлено: одинаковая source/image конфигурация и операторская
проверка исходного SQL-case снова confirmed. Не выводи воспроизводимость всего
benchmark из повторяемости одного verifier case.

Не запускай новый долгий Stage2 только ради количества. Достаточность K02
основана на сохраненном baseline; K01 на проверенном повторном lifecycle.
Provisioning отдельно от измеряемых циклов. При blocker не объявляй done.

## 3. Проверки и Definition of Done

1. Адресные tests для K02 failure logging и K01 pinning/lifecycle.
2. Полный `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q`.
3. Ruff по tracked + новым Python, не по посторонним tmp/ultra-os.
4. `git diff --check`, deterministic `python -m app.main`.
5. Запечатанные старые результаты не изменились, target sources чистые,
   нет secrets и leftovers, main/ветка не сменились.

Верни `docs/k01-k02-qwen-result.md`: какие файлы изменены, команды тестов,
live run IDs, конфигурации, что выполнено/не выполнено, blockers,
границы вывода и сколько заняла работа. Не требуй git clean рабочего дерева:
чужие `.pyc`/untracked преднамеренно сохраняются.

R01 НЕ входит в твое поручение: ее противоречия рассмотрены отдельно.
Не редактировать `contracts/examples/r01`, `docs/r01-*`, `tests/test_r01_*`.
