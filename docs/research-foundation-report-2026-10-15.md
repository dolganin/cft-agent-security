# R00–R03: исследовательская среда агента

Дата: 15 октября 2026. Ветка: `codex/r00-r03-research-foundation`.
Основа разработки: `40f6633`, включающая `origin/main` `9f12427` и ранее
опубликованные B05/B07/B09. Исторический B09 выполнялся кодом `149759a`.
Это три разных роли commit, а не три baseline-прогона.

## Что выполнено

| Задача | Результат | Проверка |
|---|---|---|
| R00 | Зафиксирован baseline, правила оценки и происхождение | 742/742 файла ZIP проверены, 12/12 offline outputs идентичны |
| R01 | Проверены закреплённые исходники трёх проектов, выбран shortlist | Permalink/SHA каждого изученного файла, лицензии и manifests |
| R02 | Файловые инструменты, постоянный workspace, Python/Node scripts | Реальные Docker checks: чтение, поиск, запись, запуск, ограничения и cleanup |
| R03 | Сервисный HTTP broker, opaque роли, точечные write grants | Реальный transport fixture + public HTTP smoke на Juice Shop |

Все новые действия используют канонические ActionProposal → PolicyValidator →
SafeExecutor → persistent execution/audit → Evidence. Действия включаются только
с `policies/research.yaml` и живой операторской ResearchRuntime. Исторические
policies/profiles/A04 labels и Gate остаются совместимыми.

Обычный reasoning-граф пока не выбирает новые инструменты: это R04. Новый CLI
`app.research_plan` позволяет уже сейчас выполнить структурированный план действий
через те же границы. Общие observations всегда имеют inconclusive; независимые
claim protocols/replay появятся на R06. Число confirmed в benchmark здесь не менялось.

## Baseline

Исходный архив: `artifacts/handoffs/b09-single-2026-10-15.zip`.
SHA256: `6ba2f4d4fcc23871f96f1bb141eb62bfae5b792904252cdb2ff2c28980a2d5c7`.
Новый паспорт: `artifacts/r00-baseline-2026-10-15-release/baseline-lock.json`.

Единственный валидный B09: 27 vulnerable + 8 safe original случаев;
найдены 13/27, подтверждены 5/27. Frozen A05 matcher пересчитан на копии ZIP;
12 файлов evaluation совпали побайтно. Исходный ZIP и его данные не изменялись.
Сравнение DEV/HOLDOUT и ограничения FPR сохранены. Новый DAST, MTTR, CP accuracy и
воспроизводимость агента здесь не измерялись. Итоговый будущий замер остаётся одним.

## Решение по готовым проектам

Фактически скачаны и изучены:

- Strix `87f2d783d6595d0aa557809e02c67d94e52bda05`, Apache-2.0.
- OpenHands SDK `95cb37b7f04ff281e92bfb3c3fc66573db2df38a`, MIT.
- PentestGPT `e8b1bb77d1ac00329675cec3b060aba971ec1ac8`, MIT.

Strix Docker adapter добавляет NET_ADMIN/NET_RAW, host-gateway и допускает
writable bind mounts. Для наших инвариантов его runtime требует существенной
адаптации. OpenHands обладает typed tool dispatch и configurable model base_url;
наш Validator понадобится как детерминированный custom tool boundary. SDK требует
Python >=3.12 и Pydantic >=2.13.5 — понадобится отдельное окружение/адаптер.
PentestGPT useful как пример deterministic memory/evidence, но текущие роли
FULL_ACCESS опираются на deployment isolation и provider CLI wrappers.

Shortlist для R04/R07: нынешний Python/LangGraph и OpenHands custom-tools adapter.
Сначала реализован нейтральный интерфейс инструментов; внешний код не копировался,
новые SDK dependencies не добавлены. Победитель по качеству поиска пока неизвестен.
Это статический shortlist, а не сравнение эффективности трёх агентов.
Полный транзитивный license/NOTICE аудит нужен при фактическом заимствовании.
Матрица с permalink и SHA: `artifacts/r01-harness-audit-2026-10-15-final/harness-audit.json`.

## Инструменты и данные

`tools.research.research_tool_contracts()` возвращает opt-in typed schemas:
list_source_files, read_source, search_source, write_workspace_file,
read_workspace_file, sandbox_command, target_http. Source search пока literal;
сложный анализ доступен через Python/Node script. Стандартный каталог tools не
расширяет действующую policy автоматически.

Оператор создаёт source inventory, связанный с original SHA и visible SHA.
В `/target` попадает redacted application-source projection: без .env/.git,
dependencies, solution/evaluation directories и ключей. Projection не является
копией приложения для запуска; это источник для анализа. Runtime target поднимается
оператором отдельно из закреплённого образа. Source/image binding не объявляется
независимой аттестацией бинарного кода.

Workspace живёт внутри одного Docker container. `/target` и root read-only,
`/workspace` — 16 MiB tmpfs, non-root, noexec, network=none, без host/Docker sockets.
Скрипты запускаются интерпретатором из закреплённых Python/Node binaries.
Полный immutable image ID разрешён для локального operator-built research image;
исторический SandboxPolicy по-прежнему требует repository digest.

Запуск связывается с SHA скрипта и immutable scope/source/session. Worker замораживает
одобренные bytes перед запуском. После исполнения уничтожает всю группу процессов;
отдельная operator cleanup убивает также detached descendants в этом контейнере.
Timeout, byte/output/PID/CPU/memory limits и cooperative cancellation проверены.
Script code может создавать вспомогательные файлы внутри workspace; entry digest
не является proof всех внутренних операций. Outputs остаются недоверенными наблюдениями.

HTTP выполняет отдельный фиксированный worker, подключённый к internal target network.
Сервис задаётся оператором как container ID + image ID + address; перед и после
запроса проверяются image, running state, membership в internal network и alias.
Поддержан адаптер из канонического RuntimeServiceMap: сервис разрешается ровно
в один контейнер, при неоднозначности отказ; digest map и parent session входят
в binding. Изменение map/source/worker блокируется. Сеть допускает только
зарегистрированные target containers и fixed workers этой research session;
target с дополнительной сетью или опубликованными портами отклоняется.
Соединение идёт на проверенный private container IP, без external DNS и без redirects.
Модель задаёт local path/method/body; Host/Cookie/Authorization ей недоступны.
GET/HEAD используют read prefixes, writes — exact operator grants.
Каждый запрос получает approval и учитывается в общем request budget.

Private role headers удерживаются внутри operator broker и передаются fixed worker
через stdin; в workspace, ActionProposal, scope и trace их нет. Ответы с отражёнными
credentials редактируются. Приёмка opaque ролей проведена на отдельном synthetic
transport fixture. Автоматическое создание пользователей и интеграция private
B04 broker в новый общий evidence protocol относятся к следующей интеграции;
этот отчёт не заявляет runtime access-control verdict на Juice Shop.

## Проверки

- Полный pytest: 1216 passed, 18 skipped. Пропуски: один A05 demo без заданного
  saved-artifact path; шесть Docker-boundary tests без CFT_SANDBOX_IMAGE;
  один multi-run SberLab; manager для SberLab/Autodealer и два manager Docker image
  tests; один sandbox runner image test; три SberLab session tests; opt-in stage1
  E2E; один stage2 checkout prerequisite. Пропуски не засчитаны как выполненные.
- 89 targeted tests на contracts, Validator/Executor/Evidence и новые границы прошли.
- Ruff, `python -m app.main`, `git diff --check` прошли.
- Шесть исторических Docker-boundary tests дополнительно выполнены с установленным
  digest-pinned CFT_SANDBOX_IMAGE: 6 passed. Остальные skip prerequisites не запускались.
- Финальная Docker transport acceptance: 30/30 checks, включая Python и Node,
  persistent files, symlink/traversal, stale script/source, byte/output budgets,
  egress denial, opaque session, credential redaction, writes, redirects,
  detached children, cancellation и подтверждённую очистку ресурсов.
- Real Juice Shop v20.2.0 public search через broker: HTTP 200 JSON, source window,
  audit/execution/Evidence и cleanup. Это transport smoke, без pentest/LLM/benchmark.
- LLM API calls в этих задачах: 0.

Артефакты: `r00-baseline-2026-10-15-release`, `r01-harness-audit-2026-10-15-final`,
`r02-r03-acceptance-2026-10-15-sealed`, `r03-juice-smoke-2026-10-15-map` под `artifacts/`.
Каждый пакет содержит seal. Прежние attempts сохранены отдельно и не публикуются
как дополнительные успешные результаты.

## Воспроизведение

Из feature-ветки с установленными project dependencies:

```bash
python -m app.research_baseline --output artifacts/r00-fresh
docker build -f executor/research.Dockerfile -t cft-research-runtime:r02 .
RESEARCH_IMAGE="$(docker image inspect cft-research-runtime:r02 --format '{{.Id}}')"
python -m app.research_acceptance --worker-image "$RESEARCH_IMAGE" --output artifacts/research-fresh
python -m app.research_juice_smoke --checkout /absolute/path/to/pinned/juice-shop --worker-image "$RESEARCH_IMAGE" --output artifacts/juice-smoke-fresh
```

Dockerfile закрепляет base digests текущего ARM64 окружения. Для другой платформы
оператор заново закрепляет совместимые base/image digests и записывает их в run scope.
Никакие packages во время measurement не устанавливаются.

Для своего плана: `python -m app.research_plan --profile <operator-target.yaml>
--checkout <target-checkout> --operator-config <config.json> --plan <actions.json>
--output <fresh-directory>`. Это trusted operator CLI, не публичный API для выбора
произвольных путей. Configuration: worker_image, source_files, services, network_name.
Action: tool, parameters, purpose, expected_evidence; HTTP дополнительно service/endpoint.
Для канонического service registry configuration принимает runtime_service_map +
http_grants вместо services/network_name. Target, binding, session и action ID создаёт приложение. CLI generic transport пока
anonymous; authenticated integration использует private operator ResearchRuntime API.

Следующий этап R04 подключает эти инструменты к самостоятельному исследовательскому
циклу, снимает early stop для разрешённых source/script действий, добавляет ledger,
budget accounting и выбор следующего эксперимента. R06 определяет independent verdict.
