# Stage 1 — Fix Verification

Дата: 9 октября 2026 года. Реализуется только этап 1; этапы Benchmark,
DAST comparison, новые security capabilities и PR automation не реализуются.

## Состояние отчёта

**Stage 1 завершён по Definition of Done.** Два последовательных реальных
Docker прогона Juice Shop получили **FIXED / security_verified=true**. Backend,
frontend, build, typecheck, Ruff и diff checks завершены без failures.
Original target immutable и cleanup подтверждены обоими artifacts и отдельной
проверкой отсутствия оставшихся fix containers/networks. Этапы 2–5 не реализованы.

## Что было до изменений

Demo готовил `ProposedPatch`, проверял его через `PatchReviewArtifact`,
ограничивал файл/окно изменений, формат diff, контекст, секреты и совместимость
Sequelize placeholders. Предложение оставалось `applied=false`,
`security_verified=false`.

Старый `FixVerificationService` создавал временную копию, применял diff и
запускал переданные `FixCheck.argv` на хосте. Его verdict зависел от exit code
static/runtime команд. Отдельного воспроизведения BEFORE, повторения той же
security capability AFTER и полноценной проверки provenance Evidence не было.

## Изученные компоненты

| Область | Ключевые файлы |
| --- | --- |
| Контракты Finding, Action, Evidence, Report | `schemas/finding.py`, `schemas/action.py`, `schemas/evidence.py`, `schemas/security_tools.py`, `schemas/report.py`, `schemas/fix.py` |
| Agent, исходники, маршрутизация | `agent/nodes.py`, `agent/verification.py`, `agent/repository_scout.py`, `discovery/profile.py`, `discovery/express_routes.py`, `tools/repository_source.py` |
| Разрешения и выполнение | `validator/validator.py`, `policies/default.yaml`, `executor/executor.py`, `executor/approvals.py`, `executor/sandbox.py`, `executor/sandbox_runner.py`, `executor/worker.py` |
| Managed runtime | `executor/sandbox_manager.py`, `executor/sandbox_session.py`, `executor/runtime_service_map.py`, `executor/sandbox_policy.py`, `schemas/target.py` |
| Evidence и итог | `evidence/store.py`, `evidence/audit.py`, `evidence/interpreter.py`, `evidence/guard.py`, `reporting/builder.py`, `pipeline/gate.py` |
| API, хранение, demo | `api/store.py`, `api/registry.py`, `api/service.py`, `app/demo.py`, `targets/juice-presentation.yaml`, `docs/demo/compose.yaml` |
| Patch и UI | `fix_verification/proposal.py`, `fix_verification/review.py`, `fix_verification/service.py`, `app/fix_verify.py`, `frontend/src/components/demo/PatchProposalPanel.tsx`, `frontend/src/api/client.ts`, `frontend/src/api/types.ts` |
| Проверки | `tests/test_patch_review.py`, `tests/test_fix_verification.py`, `tests/test_bounded_verification.py`, `tests/test_executor.py`, `tests/test_evidence_guard.py`, Docker integration tests, `pyproject.toml`, `frontend/package.json` |

Этапы 2–5 учтены через machine-readable итог, durations, отдельный fix artifact
и повторяемую capability binding. Метрики benchmark, DAST и PR не добавлены.

## Архитектурное решение

```text
confirmed finding + исходное runtime Evidence
→ existing patch proposal
→ strict patch review + source/proposal digests
→ bounded disposable snapshot
→ BEFORE: Docker prepare/build/tests/start/smoke
→ exact original security capability через Validator/Executor
→ isolated git apply --check / apply
→ AFTER: Docker prepare/build/tests/start/smoke
→ та же security capability и binding
→ persistent Evidence + audit + Evidence Guard
→ FIXED / NOT_FIXED / REGRESSION / INCONCLUSIVE / REJECTED
```

Исходный и исправленный snapshot запускаются в разных одноразовых контейнерах.
Build/tests используют network `none`; startup и bounded проверки — внутреннюю
Docker network. Source mount — read-only, рабочий target находится в container
tmpfs. Dependencies/frontend assets заранее предоставляются pinned image.

## Внесённые изменения

| Файл | Назначение и изменение |
| --- | --- |
| `AGENTS.md` | Зафиксированы Stage 1 workflow, registered fix capability, security_verified guards и integration command. |
| `docs/stage1-fix-verification-report.md` | Этот итоговый отчёт: изменения, источники, результаты, digests, replay и реальные ограничения. |
| `schemas/target.py` | Операторский `TargetFixConfig`: adapter/image/service/source commit, timeout и общий wall-clock budget; команд в конфигурации нет. |
| `schemas/fix.py` | Структурированный полный fix artifact, статусы, before/after Evidence digests, patch/source digests, этапы, duration, cleanup; guard для `security_verified`. |
| `schemas/security_tools.py` | Явный отрицательный verdict `rejected` для bounded verification. |
| `fix_verification/review.py` | Сохранение editable window; CRLF с сохранением source bytes; replay canonical annotations; раннее отклонение trailing whitespace. |
| `fix_verification/workspace.py` | Ограниченный snapshot, path/link/reparse/hardlink checks, digest binding, strict review replay, fixed git check/apply и проверка полного manifest после patch. |
| `fix_verification/service.py` | Новый BEFORE/apply/AFTER workflow, доверенная original binding, Validator/Executor, проверка persisted record и audit, Evidence Interpreter/Guard, cleanup и финальный verdict. Удалён host argv runner; входные модели заморожены, перед apply review проверяется повторно; bootstrap подтверждения использует тот же phase runner. |
| `executor/fix_runtime.py` | Одноразовый Docker adapter с фиксированными prepare/build/tests/start/smoke этапами, resource limits, read-only mount, tmpfs, внутренней сетью и cleanup. |
| `executor/executor.py` | Зарегистрирован `fix_target_stage`; только matching bound Docker runtime, persisted action digest, redaction output. |
| `executor/worker.py` | SQL-проверка различает явное повторяемое блокирование probe и техническую неопределённость. |
| `evidence/interpreter.py` | Независимая перепроверка отрицательного SQL результата по structured observations. |
| `validator/validator.py`, `policies/default.yaml` | Детерминированные contracts для fix stages; extra argv/endpoint/host отвергаются. |
| `discovery/profile.py` | Сохранение операторского fix config при расширении TargetProfile через Discovery. |
| `app/fix_verify.py` | CLI принимает report/review/operator profile/output; произвольный YAML argv plan больше не выполняется. |
| `app/demo.py` | GET/POST fix-verification, отдельное атомарное хранение artifact; исходный report/Gate не перезаписываются; diff сохраняется без Windows newline translation. |
| `frontend/src/api/types.ts`, `frontend/src/api/client.ts` | Контракт и вызовы Fix Verification API. |
| `frontend/src/components/demo/PatchProposalPanel.tsx` | Кнопка запуска, before/after, статусы этапов, applied/security_verified, integrity/cleanup. |
| `frontend/src/components/demo/PatchProposalPanel.test.tsx` | Проверка отображения verified fix отдельно от patch proposal. |
| `tests/test_fix_verification.py` | Интеграция через реальный Validator/Executor/persistence/interpreter с fake Docker transport; негативные cases и immutable original snapshot. |
| `tests/test_executor.py` | Обновлён ожидаемый зарегистрированный tool catalog. |
| `tests/test_patch_review.py`, `tests/test_repository_scout_source.py` | Byte-based digest assertions и явные Windows symlink skips. |
| `app/stage1_e2e.py` | Официальный preflight/confirmation/review/verification/integrity entrypoint; существующие report/review либо свежая реальная confirmation, без mock Docker и без обращения к LLM. |
| `tests/test_stage1_e2e.py` | Preflight/proposal unit checks и opt-in два реальных последовательных Docker прогона. |
| `executor/fix_test_reporter.mjs`, `pyproject.toml` | Компактный failure/skip/summary reporter, отдельный read-only mount и включение в package data. |
| `docs/demo/README.md` | Одна команда E2E, provisioning prerequisites и Windows LF checkout. |
| `docs/demo/fix-verification.Dockerfile` | Provisioning image с Node/TypeScript/server test dependencies и frontend assets; verification работает по digest без download/install. |

## Security guarantees

- Original target не передаётся как writable mount и не получает patch.
  Snapshot проверяется до/после копирования и после завершения; patch меняет
  ровно один разрешённый existing file без mode change.
- Symlinks, Windows reparse paths, hardlinks, traversal, неожиданные новые
  файлы, rename/mode metadata отвергаются.
- Модель предлагает только diff. `fix_target_stage` принимает adapter/stage,
  extra `argv` отклоняет Validator; runtime берёт команды из собственного
  фиксированного adapter, не из model output/package.json scripts.
- Исходные artifact/line/service/endpoint/mode выводятся из операторского
  профиля и сверяются с confirmed runtime Evidence. BEFORE/AFTER получают
  одинаковые параметры; меняются только уникальный action id/session.
- Persisted Evidence проверяется по run/action/tool/target/proposal digest,
  output, audit evidence digest и Docker backend. SQL verdict перепроверяется
  существующим interpreter и Evidence Guard.
- Просто stdout `confirmed`, успешный build или текст модели не дают FIXED.
  BEFORE должен быть confirmed, AFTER — explicitly rejected, обязательные
  этапы — passed, cleanup и original integrity — подтверждены.
- `sandbox_command` и существующий CI Gate не получают новых обходных путей.
  Fix artifact хранится отдельно от оригинального finding report/Gate.

## Open-source reference

Код сторонних проектов не скопирован, новые зависимости на них не добавлены.

- [VulnHunter](https://github.com/capitalone/VulnHunter), Apache-2.0:
  изучены README, `vulnhunter-fix/SKILL.md`, `vulnhunt-fix-verify/SKILL.md`
  и verifier README. Использована идея RED-before/GREEN-after и независимого
  Evidence-backed verdict. Standalone verifier upstream является статическим
  prompt-only проверяющим; наш runtime verifier остаётся существующей capability.
- [SWE-agent](https://github.com/SWE-agent/SWE-agent), MIT:
  изучены `sweagent/environment/repo.py`, `sweagent/environment/swe_env.py`,
  LICENSE. Использованы идеи disposable repository copy, base commit и
  отделения deployment/runtime от reasoning. Host reset/clean и shell pipeline
  upstream не переносились.
- Проверены [VulnHunter LICENSE](https://github.com/capitalone/VulnHunter/blob/main/LICENSE)
  и [SWE-agent LICENSE](https://github.com/SWE-agent/SWE-agent/blob/main/LICENSE).

## Полученные результаты проверок

| Проверка | Точная команда | Реальный результат |
| --- | --- | --- |
| Full backend | `python -m pytest -q -ra` с pinned `CFT_SANDBOX_IMAGE` | **448 passed / 15 skipped / 0 failed**, 34.94 s |
| Fix Verification | `python -m pytest tests/test_fix_verification.py -q -ra` | **29 passed / 1 skipped / 0 failed**, 7.44 s |
| Fix + PatchReview + entrypoint | `python -m pytest tests/test_fix_verification.py tests/test_patch_review.py tests/test_stage1_e2e.py -q -ra` | **56 passed / 3 skipped / 0 failed**, 7.82 s |
| Docker boundary/runtime | `python -m pytest tests/test_docker_sandbox_boundary.py tests/test_sandbox_runner_integration.py tests/test_sandbox_manager_integration.py -q -ra` | **6 passed / 5 skipped / 0 failed**, 11.03 s |
| Frontend | `npm.cmd test -- --maxWorkers=1 --no-file-parallelism` | **28 passed**, 8 test files, 98.91 s |
| Frontend typecheck | `npm.cmd run typecheck` | **PASS** |
| Frontend production build | `npm.cmd run build` | **PASS**, TypeScript + Vite, 771 ms Vite build |
| Ruff | `python -m ruff check .` | **PASS** |
| Whitespace | `git diff --check` | **PASS** |
| Manual LangGraph | `python -m app.main` из корня | **PASS**, confirmed, 1 iteration, 1 Evidence |
| Real repeated Docker E2E | `CFT_RUN_STAGE1_E2E=1 python -m pytest tests/test_stage1_e2e.py -m integration -q -s` | **1 passed / 3 deselected**, два полных реальных цикла, 463.68 s |

Отдельный Python typechecker и frontend lint script в конфигурации не заданы;
новые инструменты ради проверки не добавлялись.

Логи находятся в `artifacts/stage1-checks/stage1-*.txt`; полный список skips
записан в `artifacts/stage1-checks/stage1-backend-tests.txt`. Реальный replay log:
`artifacts/stage1-checks/stage1-real-integration.txt`. Временные каталоги
первоначальных sandbox tests удалены; их зависшие процессы остановлены.

Классы 15 skips полного backend suite:

- 4 проверки реальных symlinks: Windows не предоставляет нужную privilege.
- 1 POSIX resource-limit test: Windows platform.
- 9 integrations: отсутствуют SberLab/Autodealer checkout (включая fixtures
  для process/compose/framework/runner/cancellation lifecycle).
- 1 дорогой Stage 1 E2E: требует явного `CFT_RUN_STAGE1_E2E=1`; отдельно он
  выполняется с opt-in. Это не отсутствие image: pinned images уже подготовлены.

В upstream Juice Shop server tests есть **2 собственных skip:true**:
`rceChallenge` infinite loop и `rceOccupyChallenge` timeout. Они не были включены
или переписаны нашим adapter. После patch: **413 passed / 2 skipped / 0 failed**.
В первом BEFORE summary: **400 passed / 2 skipped / 0 failed**; fixture bootstrap
и AFTER возвращали **413 passed / 2 skipped / 0 failed**. Все обязательные
server-test команды завершились exit 0; summary сохранён без подмены.

## Исправленные реальные проблемы

1. Первые full-suite failures: ожидаемый Executor catalog не содержал новой
   capability; Scout symlink test не обрабатывал WinError 1314. Исправлено,
   финальный full suite проходит.
2. Windows sandbox запрещал `Path.resolve(strict=True)` даже для созданных
   файлов (WinError 5). Файловые security tests запускались через разрешённый
   execution вне этого sandbox; границы runtime security-agent не менялись.
3. Windows CRLF checkout менял byte representation публичного ключа Juice
   Shop и ломал два исходных JWT-теста в Linux. Подготовлен **отдельный clean LF
   clone** того же commit. Исходный CRLF checkout не переписывался.
4. `NODE_ENV=test` отключает `configureApp` в Juice Shop и не предоставляет
   product-search routes. Только registered startup использует application
   `NODE_ENV=production` внутри disposable Docker; `TargetProfile.environment`
   остаётся **sandbox**, external network запрещена. Tests используют upstream
   test-env helper как раньше. Security-sensitive target code не менялся.
5. Canonical PatchReview содержит оригинальные annotation comments, тогда
   как первоначальное model window очищено. Replay теперь допускает **точный
   raw source или его известное очищенное представление**, с прежними digest,
   file/window/count/credential guards. Добавлен regression test.
6. Integration proposal сохранял пробел после удалённого comment. Strict
   `git apply --whitespace=error --check` правильно отклонял его. Proposal
   исправлен; PatchReview теперь отвергает такие additions до запуска BEFORE.
7. Docker server tests теперь выводят bounded failures/skips/summary через
   operator-owned reporter. CLI корректно печатает Unicode на Windows.
8. Proposal/report/profile заморожены на время проверки, а review повторно
   проверяется непосредственно перед apply. Замена caller-owned proposal
   во время BEFORE не может подменить применяемый patch.

## Реальный Juice Shop E2E

Target: `artifacts/stage1-juice-shop`, clean LF checkout OWASP Juice Shop v20.2.0.
Commit: `5658473cf8814459bf89000ce373b20ed0b4eb37`.
Finding: `sequelize-injection.presentation:routes/search.ts:23`.

Первый успешный run: `stage1-26db3b3fce974aae9810d1aa046053e9`.
Fix artifact: `fix-185c231dadf745fbb52443834e9eadfa`.
Duration самого Fix Verification: **148030 ms** (bootstrap confirmation отдельно).

Второй run: `stage1-4dcc0cd9d7b04e55bcf62d8cab3247f9`.
Fix artifact: `fix-21125e70104142b69ec28478595a604c`.
Duration: **145610 ms**. Вновь BEFORE CONFIRMED, AFTER REJECTED, все 10 stages
passed, original_unchanged=true, cleanup_complete=true, security_verified=true.

| Run | BEFORE session | AFTER session |
| --- | --- | --- |
| 1 | `cft-fix-0902be376d04428c945c` | `cft-fix-36210368af0a44bc8ca2` |
| 2 | `cft-fix-5d1fab77bc4e444baec5` | `cft-fix-0b75c31722dc4682b7af` |

Проверены разные workspace/session ids, одинаковые trusted bindings, source,
patch и patched digests, одинаковый logical security verdict. Source manifest
SHA-256 обоих runs: `4b296a6765b195a64b570c3703678f766b8ccb7f5d93a8a4b7a66d4241f1337c`.
Второй BEFORE и AFTER: 413 server tests passed / 2 upstream skips / 0 failures.
Финальные `docker ps --all --filter name=cft-fix-` и `docker network ls --filter
name=cft-fix-` вернули пустой список; оба original checkout имеют clean git status.

| Этап | Реальный результат |
| --- | --- |
| Original confirmation | CONFIRMED через реальный Docker worker, Interpreter и Guard |
| PatchReview | ready_for_review, policy sequelize_search_review_v1 |
| BEFORE prepare/build/tests/start/smoke | Все passed |
| BEFORE verify_sql_injection | **CONFIRMED** |
| Isolated dry-run/apply + manifest | passed; изменён только routes/search.ts |
| AFTER prepare/build/tests/start/smoke | Все passed |
| AFTER verify_sql_injection | **REJECTED** |
| Evidence integrity | PASS: persisted execution + action digest + audit evidence digest + Guard |
| Original commit/file/tree/git status | До и после равны; clean |
| Cleanup | true |
| Final | **FIXED**, applied=true только относительно disposable workspace, security_verified=true |

Exact trusted binding BEFORE/AFTER:

```json
{
  "tool": "verify_sql_injection",
  "target": "juice-presentation",
  "environment": "sandbox",
  "parameters": {
    "artifact_id": "source-d35652ee4d560380",
    "line": 23,
    "check": "sql_interpolation",
    "mode": "search"
  },
  "service": "juice",
  "endpoint": "/rest/products/search"
}
```

Query parameter `q` принадлежит fixed search capability и не задаётся моделью.
Новые action/session ids закономерно отличаются.

Digests первого успешного run:

| Значение | SHA-256 |
| --- | --- |
| Original search.ts | `de09bfc4040fc88073dbb85a7d1ef0171388abb4775eedc78578a48167853057` |
| Reviewed patch | `4966691d48839a3c9074bddfd0e513e01d5b0adf13afad5f43ebed767c08fa8b` |
| Patched search.ts | `fc0cfa64dadbc2eaeda40a53969362232ac4f56806e34644c8bb81820b4b3bbc` |
| BEFORE Evidence | `5e20ff4a017acfd1ba0158c183312bf953c0032192624ec09acfe1df0f9881d8` |
| AFTER Evidence | `ab70bb59666be589e958798f2def12183a7322daa0b96c2aaf58bde8c5b84d7d` |

Images:

- Worker: `python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4`.
- Fix: `cft-fix-juice@sha256:b3c854f853e6bb2f2b5bd261d1766c11904afd1bc497b481d2b9a3b77033c9c5`.

Provisioning Dockerfile реально собрался. Target application source не
встроен в fix image: source берётся из проверенного snapshot; image содержит
Node dependencies и заранее собранные frontend assets. У upstream нет lockfile,
поэтому повторная provisioning сборка может дать другую dependency tree.
Для повторения используйте сохранённый **image digest**. Никакие downloads или
npm install во время BEFORE/AFTER не выполняются.

Artifact directory:
`artifacts/stage1-real-integration/test_real_juice_fix_verificati0/stage1-26db3b3fce974aae9810d1aa046053e9/`.
Здесь сохранены original-before/after, confirmed report, review, fix artifact,
image/profile configuration, execution Evidence и JSONL audit.

## Integration entrypoint

Официальный entrypoint: `app/stage1_e2e.py`.

```bash
python -m app.stage1_e2e
```

Prerequisites: Docker, clean LF target нужного commit и provisioned local images.
Подготовка описана в `docs/demo/README.md`. Preflight не скачивает images;
локальные tags разрешаются однократно в immutable RepoDigest.

По умолчанию фиксируется известная integration finding; свежая confirmation
получается реальным runtime (source="integration_fixture", не выдуманный SAST
run). Зарегистрированное deterministic SQL proposal проходит тот же
PatchProposalService/strict PatchReview. `--report` и `--review` позволяют
загрузить штатные ранее сохранённые artifacts. Модель/новый агент не требуются.

Output: `artifacts/stage1-e2e/stage1-<unique-id>/fix-verification.json` вместе с
полной цепочкой provenance. Exit 0 требует security_verified=true; exit 1 —
завершённая проверка без verified fix; exit 2 — preflight/bootstrap failure.

## Реальные ограничения Stage 1

- Сейчас provisioned adapter покрывает Node/TypeScript Juice Shop; для других
  проектов требуется operator-owned adapter/configuration, произвольные scripts
  из repository не подхватываются автоматически.
- Проверяется backend build, server unit suite и фиксированный functional smoke.
  Target frontend взят из pinned image; browser/Cypress и весь API attack suite
  Juice Shop не запускаются этим profile.
- REJECTED доказывает блокирование **точного исходного bounded SQL probe**, а
  не отсутствие всех возможных SQL injection вариантов или всех уязвимостей.
- Snapshot ограничен размером/числом файлов; linked/reparse/hardlinked paths
  отвергаются. Git metadata, dependencies и generated build/dist не копируются
  в source manifest; commit и clean git status дополнительно проверяются entrypoint.
- Symlink/POSIX и внешние SberLab/Autodealer tests имеют реальные platform/fixture
  skips, перечисленные выше.
- Dependency tree provisioned image фиксируется digest; upstream lockfile
  отсутствует. Повторение provisioning без сохранённого image может отличаться.
- Demo API/UI требуют operator-owned `TargetProfile.fix_verification` с
  provisioned image digest; без конфигурации возвращается INCONCLUSIVE.
  Официальный E2E entrypoint делает эту binding из preflight-checked local image.
  В README приведена конфигурация для подключения demo UI.
