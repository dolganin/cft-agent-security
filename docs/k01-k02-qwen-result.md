# K01 + завершение K02: результат NSU Qwen worker

Дата: 2026-10-11. Модель: `nsu/qwen3.8-flash-next`, reasoning `xhigh`, OpenCode
`1.19.0`, `--pure`. Ветка `codex/s01-integration-contracts`, HEAD `a6ca5db6a1a5aae3c27735c82d1ad41fdd68934e`
(не менялся). Git add/commit/push/stash/reset не выполнялись. R01 не тронута:
`contracts/examples/r01/`, `docs/r01-*`, `tests/test_r01_specifications.py` не
открывались на запись и не изменялись.

## 1. Изменённые файлы

| Файл | Статус | Что изменилось |
|---|---|---|
| `evaluation/baseline_diagnostics.py` | untracked (K02-файл) | `launch_failure`-ветка для `subprocess.Popen`, валидация имени stage, рекурсивное редактирование конфигурации попытки |
| `tests/test_baseline_diagnostics.py` | untracked (K02-файл) | +14 тест-кейсов (16 → 30): missing executable, preflight-вариант, missing cwd, redaction вывода и конфигурации, небезопасные stage-имена (8 параметров), ненулевой CLI exit |
| `schemas/target.py` | modified | `TargetFixConfig.image` принимает `name@sha256:<64 hex>` **или** полный image ID `sha256:<64 hex>`; добавлены `is_immutable_image_id` / `is_repository_digest` |
| `app/stage1_e2e.py` | modified | `pinned_image` резолвит operator-ссылку в immutable ref (RepoDigest → иначе реальный image ID из `docker image inspect`), новая `digest_pinned_worker_image` для worker |
| `tests/test_stage1_e2e.py` | tracked | обновлены 2 теста pinning под новый контракт + 1 новый тест локальной сборки |
| `tests/test_k01_environment.py` | new | 24 теста pinning/структуры паспорта |
| `docs/k01-environment-passport.md` | new | паспорт окружения (K01) |
| `docs/k02-baseline-diagnostics.md` | untracked (K02-файл) | добавлен раздел follow-up: результат сверки артефактов и описание починки launch-failure |
| `docs/demo/README.md` | tracked | описание новых правил immutable-ссылки |
| `docs/k01-k02-qwen-result.md` | new | этот отчёт |

Каталоги результатов: новый `artifacts/k01-2026-10-11-stage1-lifecycle-8f2c1a7d/`.
Старые `artifacts/k02-2026-10-11-*`, `artifacts/presentation-2026-10-08`,
`artifacts/security-pipeline` не изменялись и не дополнялись.

## 2. K02: отказ запуска больше не теряется

Проблема: `subprocess.Popen` в `run_attempt_stage` мог бросить `OSError`, запись
оставалась `RUNNING`, финальный журнал не создавался.

Поведение теперь:

- `launch_failure=true`, `status=FAILED` (или `PREFLIGHT_FAILED` для `preflight`),
  `exit_code=null`, `timed_out=false`, `started_at`/`finished_at`/`duration_seconds`
  сохраняются;
- в `<stage>.stderr.txt` пишется строка `Launch failed before process creation:
  <Type>: <redacted message>`, `<stage>.stdout.txt` — пустой;
- `attempt.json` после отказа имеет тот же терминальный статус, `RUNNING` не
  остаётся; CLI `run` возвращает `2` (нет exit code) — ненулевой код;
- отказ запуска не является timeout и не является security finding; отдельного
  запуска Stage2 ради этого не делалось.

Дополнительно:

- `validate_stage_name()` вызывается до любых записи: только токен
  `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` без `..`, без `/` и `\`, без пробелов, иначе
  `ValueError` и ни одного файла;
- `create_attempt()` прогоняет configuration через `redact_value()`: паттерны секретов
  плюс значения полей, чьё имя заканчивается на `apikey|authorization|clientsecret|
  credential|credentials|key|passwd|password|secret|token`.

Downstream consumers проверены: `Validator`/`Executor`/`SandboxPolicy` читают только
`fix_verification.adapter` и `service`, `discovery/profile.py` копирует объект целиком
(`model_copy`/`model_dump` не зависят от способа валидации), `fix_runtime` использует
`config.image` как единственный аргумент образа в `docker run`. Паттерн валидации не
расширен на mutable tag, поэтому ослабления нет.

## 3. K02: сверка утверждений по артефактам

Проверено read-only по запечатанным файлам, историю не переписывали:

| Утверждение | Источник | Результат |
|---|---|---|
| seal 47 файлов | `stage2-output/run-001/seal.json` (49 строк = 47 записей + скобки) | подтверждено |
| 10 FinalReport | `run-001/pipeline/reports/` (10 файлов) | подтверждено |
| TP/FP/FN/TN = 5/0/5/2 | `scorecard.json` | подтверждено |
| confirmed = 4, verified recall = 0.4 | `scorecard.json`: `verified_positives=4`, `verified_recall=0.4` | подтверждено |
| «recall по confirmed = 0.5» не писать | `scorecard.json`: `recall=0.5` — это detection recall, отдельная метрика | расхождение не найдено; документ различает 0.5 (detection) и 0.4 (verified) |
| 6 inconclusive, false confirmations = 0 | `verification_statuses`, `false_confirmations=0` | подтверждено |
| Stage1: FIXED, BEFORE confirmed, AFTER rejected, 10 стадий, original unchanged, cleanup | `fix-verification.json` | подтверждено |
| Stage1 — operator `IntegrationPatchClient`, не генерация моделью | `patch-review.json`, `app/stage1_e2e.py` | подтверждено |
| ActionProposal отсутствует, не додумана | `current-v1-diagnostic.json`, chain `action_proposal=missing` | подтверждено, осталась unresolved |
| credentials в attempt/выводе | regex-скан attempt.json + stdout/stderr обоих attempts | совпадений нет |
| архивные `artifacts/security-pipeline/reports/*.json` | `legacy-reports-diagnostic.json` | 4 schema-несовместимости, не мигрированы |

Ограничение K02 остаётся: один прогон v1, пять FN, шесть inconclusive, отсутствие
сериализованного canonical `ActionProposal`.

## 4. K01: pinning локальной сборки

- `TargetFixConfig.image` — единственный shared-контракт, через который образ попадает
  в runtime. Теперь принимаются две immutable-формы; mutable tag (`name:tag`,
  `:latest`), усечённый/65-символьный/верхнерегистровый digest и пустая строка
  отклоняются `ValidationError` с текстом про `immutable`.
- `pinned_image()` сначала проверяет форму ссылки (невалидный `sha256:…` или
  `…@sha256:…` отклоняется **до** обращения к Docker), затем выполняет ровно
  `docker image inspect <ref>` и:
  - image ID → сверяется с `Id` из inspect;
  - repo digest → возвращается как есть (inspect доказал наличие образа);
  - operator tag → первый валидный RepoDigest, иначе полный `Id` из inspect;
  - ни того ни другого → `ValueError`.
- Пулл-команда не вызывается ни в одной ветке; runtime по-прежнему `--pull never`.
  Тесты фиксируют, что в argv нет `pull`, а malformed-ссылка не доходит до Docker.
- Worker-образ отдельно ужесточён: `digest_pinned_worker_image` требует
  `name@sha256:<64 hex>`, потому что `SandboxPolicy.__post_init__` требует `@sha256:`
  в `sandbox_image`. Локальный worker без RepoDigest честно не поддерживается.

Границы сохранены: `--pull never`, networkless `prepare/build/tests`, readonly
mount исходников, внутренняя сеть только для `start/smoke`, `--user 1000:1000`,
`--read-only`, `--cap-drop ALL`, `no-new-privileges`, бюджеты. Runtime не рефакторен:
изменены только `app/stage1_e2e.py` и shared-контракт в `schemas/target.py`.

Совместимость: `tests/test_fix_verification.py`, `tests/test_target_profile.py` и
`tests/test_stage1_e2e.py` используют digest-форму и проходят без изменений
кроме двух обновлённых тестов pinning.

## 5. K01: реальный повторный жизненный цикл

Первый цикл зачтён как K02 `k02-2026-10-11-stage1-cd97a2e4` /
`stage1-a5b899ec304240b79fae53411adcb0ec` после проверки исходных manifests:
`attempt.json` фиксирует target commit `5658473c…`, tree `72d28625…`, те же
image IDs/RepoDigests, что показывает живой `docker image inspect` сейчас
(`cft-fix-juice@sha256:cdb8246f…de0d`, `python@sha256:1b668429…4ab4`,
`bkimminich/juice-shop@sha256:8739101a…526b`).

Второй цикл — новый прогон того же подготовленного pinned target, другой output
каталог:

```bash
env -u NSU_OPENWEBUI_KEY PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m app.stage1_e2e \
  --target artifacts/k02-2026-10-11-stage1-cd97a2e4/juice-shop \
  --worker-image python:3.12-alpine --fix-image cft-fix-juice:stage1 \
  --output-dir artifacts/k01-2026-10-11-stage1-lifecycle-8f2c1a7d
```

| | цикл 1 (K02, sealed) | цикл 2 (новый) |
|---|---|---|
| run ID | `stage1-a5b899ec304240b79fae53411adcb0ec` | `stage1-379c3d3dd66c471bb54f722d59607dd8` |
| fix ID | `fix-b762400054fb4b33bf717f60a65a8ab8` | `fix-de15979160ef460f9b4fdf10ebf132da` |
| baseline artifact | `baseline-5f3c672b10c94c609514426a3dc35876` | `baseline-f777d304606b4c63930dfbf3feb966ff` |
| BEFORE session / run | `cft-fix-d43abb50db394d2fb61d` / `31c841d869bc47748875d5a030c3e79f` | `cft-fix-16c62cb3d2b94fc9bfb0` / `233ecb8075b94371856950058695dd66` |
| AFTER session / run | `cft-fix-cf03cfae158846aeadb6` / `923e4f03caee4ad4b5b955a31382d7a1` | `cft-fix-743144c056f3462b973b` / `3940496ecd8b476e8ca872ad8b9f5898` |
| baseline-confirm / verifier | 27 200 ms / 50 544 ms | 23 048 ms / 48 499 ms |
| стадии | 10/10 passed, 415 тестов (413 pass, 2 skip) | 10/10 passed, 415 тестов (413 pass, 2 skip) |
| итог | `FIXED`, `security_verified=true` | `FIXED`, `security_verified=true`, exit 0 |

Frozen-сверка циклов: одинаковые commit `5658473cf8814459bf89000ce373b20ed0b4eb37`,
tree `72d28625be8887357e9c53de485f96fe3ea6c5e8719253b9318d755b4fc9a753`,
`routes/search.ts` `de09bfc4040fc88073dbb85a7d1ef0171388abb4775eedc78578a48167853057`,
worker/fix образы, `policy_sha256` `311d8155a2b43cc065ac33c2cdea0cfc4023a5d130dce463c12c78fb3b9e3714`
(= живой digest `policies/default.yaml`), профиль
`687ea7a6d4f9d9ad067cc53bf219ff012b9c21a503462b23e9a2938d2be9b0e1`.
Разные: output-каталог, run/fix ID, все Docker-сессии и execution/run ID стадий.

Reset: после teardown первого цикла (`cleanup_complete=true`) и нового startup из
того же immutable образа исходный SQL-case снова `confirmed` (BEFORE цикла 2).
`original-before.json == original-after.json`, `git status` target пуст и до, и после.
Это воспроизводимость одного verifier-case, а не всего benchmark.

Stage2 заново не запускался: K02 достаточен по сохранённому baseline, а живой Stage2
стоит 335 с и не входил в условие K01.

## 6. Паспорт и preflight

`docs/k01-environment-passport.md` содержит проверенные значения: macOS 26.5.2
arm64, Docker 28.5.2 (daemon linux/arm64), `.venv` Python 3.13.11 (K02-прогоны
использовали `python3` 3.11.9 — различие зафиксировано), Semgrep 1.173.0 в `.venv`
(1.174.0 в sealed K02), Node 24.21.0 внутри fix-image, commit + dirty digest
агента, target commit и байты исходников, фактические image IDs/RepoDigests,
лимиты контейнера, бюджеты, префиксы `cft-fix-*`, `cft-sandbox-*`,
`cft-target-*`, `cft-framework-*`, `cft-readiness-*`, `cft_internal_security_net`
и команды проверки отсутствии leftovers.

Три разных preflight разделены отдельно: инфраструктура (`docker info`/
`image inspect`/commit/clean), нейтральный model probe и startup приложения.
Нейтральный probe выполнен существующим project adapter:

```bash
env -u NSU_OPENWEBUI_KEY PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m app.llm_probe
# Selected route: nsu/qwen3.8-flash-next
# {"status": "ready", "note": "Model is reachable."}  ok (578ms)
```

Значения ключей не читались, не печатались и не попадали в артефакты; `.env` не
открывался. Benchmark truth модели не отправлялся.

## 7. Команды проверок и результаты

| Проверка | Результат |
|---|---|
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest tests/test_k01_environment.py tests/test_baseline_diagnostics.py tests/test_stage1_e2e.py -q` | 58 passed, 1 skipped (opt-in integration) |
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q` | **612 passed, 18 skipped** |
| `.venv/bin/python -m ruff check $(git ls-files '*.py') evaluation/baseline_diagnostics.py app/baseline_diagnostics.py tests/test_baseline_diagnostics.py tests/test_k01_environment.py` | All checks passed (tmp/ и ultra-os/ не линчились) |
| `git diff --check` | чисто |
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m app.main` | `Workflow status: confirmed`, детерминированно |
| `docker ps -a`, `docker network ls` | новых `cft-fix-*` контейнеров и сетей нет |
| `git status`, `git rev-parse --abbrev-ref HEAD`, `git rev-parse HEAD` | ветка и HEAD не изменились, staged ничего нет |

Skip-список полного прогона (все — opt-in внешние интеграции):
`tests/test_docker_sandbox_boundary.py` ×6 (нужен `CFT_SANDBOX_IMAGE`),
`tests/test_sandbox_manager_integration.py` ×3 + ×2, `tests/test_sandbox_runner_integration.py`,
`tests/test_sandbox_session_integration.py` ×3 (`SBERLAB_TARGET_PATH`),
`tests/test_multi_run_docker_integration.py`, `tests/test_stage1_e2e.py`
(`CFT_RUN_STAGE1_E2E`), `tests/test_stage2_benchmark.py` ×2.

## 8. Что не сделано и blockers

1. **Провижининг заново не выполнялся.** `git clone`, `docker pull`, `docker build`
   вне разрешённых операций этого воркера (разрешены только read-only
   `docker info/version/ps/image inspect/network ls`). Использованы ранее
   подготовленные clean-LF clone и образ; их подлинность подтверждена digest-сверкой
   с sealed K02 `attempt.json` и живым `docker image inspect`. Требуемая операция,
   если нужен полностью «с нуля» цикл: `git clone --branch v20.2.0`,
   `docker pull python:3.12-alpine`,
   `docker build --pull -f docs/demo/fix-verification.Dockerfile -t cft-fix-juice:stage1 <clone>`.
2. **Второй цикл использовал тот же подготовленный clone** (создать новый clone
   запретено п. 8). Независимость обеспечена отдельным output-каталогом, новыми
   run/fix/session ID и одноразовыми контейнерами; байты исходников доказаны
   одинаковыми, а не предположены.
3. **Worker-image без RepoDigest не поддержан** — `SandboxPolicy` требует
   `@sha256:`; менять её вне моей области. Зафиксировано как ограничение.
4. **Точная версия `python3` внутри fix-image не записана** ни в одном артефакте;
   подтверждено только то, что `python3` работает (стадии `prepare`/`start`).
   `node:24-bookworm@sha256:3d27e5c1…` отдельно в локальном хранилище отсутствует —
   остался только собранный из него образ.
5. **Повторных Stage2-прогонов нет** (не требовалось; не запускать долгий Stage2
   ради количества).
6. **Отсутствующий canonical `ActionProposal`** остался unresolved — это задача
   интеграции сериализации, предложение задним числом не придумывалось.
7.R01 не рассматривалась и не менялась.

## 9. Границы вывода и сохранность чужой работы

- Изменены только файлы из раздела 1; другие общие файлы не менялись.
  `scripts/run_qwen_k01_k02.py` не редактировался этим worker. На момент выдачи
  это untracked файл основного агента; изменение импортируемого модуля само по
  себе не меняет Git-статус импортирующего файла.
- Не откатывались и не «чищались»: чужие `__pycache__/*.pyc`, `tmp/`, `output/pdf/`,
  `ultra-os/`, untracked-планы, результаты K02/R01, `artifacts/*`.
- docker prune/stop/rm чужих контейнеров не выполнялся; предсуществовавшие
  `cft-sandbox-sequence-*` и `cft-sandbox-31200f14d4a6-juice-1` оставлены как есть.
- Секреты: `.env` не читался, ключи не выводились; вывод диагностики и attempt
  проходит redaction; regex-скан новых артефактов совпадений не нашёл.
- Рабочее дерево намеренно не clean: это ожидаемое состояние этого этапа.

## 10. Длительность

Работа воркера: около 12 минут wall-clock от первого чтения задания до финальных
проверок. Внутри этого: живой Stage 1 цикл занял ~72 с по артефактам
(`07:14:42.4Z` → `07:15:54.0Z`), из них 23 048 ms исходное подтверждение и
48 499 ms Fix Verification; нейтральный model probe 578 ms; полный pytest 10,1 с;
полный ruff — доли секунды. Остальное время — чтение документов/артефактов,
правки и адресные проверки.
