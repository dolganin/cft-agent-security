# A03 — безопасные контроли и reset

Статус: A03 выполнен с ограниченным каталогом **4 независимых ORIGINAL_SAFE controls**.
Это подготовка evaluator truth и reset, не freeze полного ground truth и не scored benchmark.
Дата: 11 октября 2026. Target: OWASP Juice Shop v20.2.0,
commit `5658473cf8814459bf89000ce373b20ed0b4eb37`.

## Источники и границы

Изучены A01 protocol/lock и split helper, текущие shared schemas; Stage 1
`fix_verification/workspace.py`, `review.py`, `service.py`, `executor/fix_runtime.py`,
`app/stage1_e2e.py`; операторский профиль `targets/juice-presentation.yaml` и
`docs/demo/`; pinned target challenge metadata, coding challenge extractor,
codefixes, annotation spans, ORM модели, auth middleware, handlers и upstream tests.
Особенно важны `server.start` с `sequelize.sync({force:true})`, `data/datacreator.ts`,
`lib/insecurity.ts`, `routes/currentUser.ts`, `routes/address.ts`, `routes/payment.ts`.

Production-компоненты, A01 frozen inputs, A02 catalog и v1 не изменены.
Добавлена отдельная схема `schemas/benchmark_controls.py`; для merge достаточно
новых A03 файлов и двух A03 правил LF в `.gitattributes`.
Новых Agent/Executor verification capabilities, scored runs, scanner baseline,
A04/A05/B/C integration нет.

## Каталог и фактические количества

Автоматически обнаружены **35 официальных correct-fix candidates**. Ещё четыре
original source cases выбраны и явно проверены вручную: всего рассмотрено 39 кандидатов.
Discovery не присваивает safe truth: связывает naming convention `key_N_correct.ext`,
`key.info.yml`, challenge category и реальные source annotation spans, сохраняет
commit, source/region/correct-file/metadata digests. Все generated candidates unverified.

| Slice | Reviewed | Runtime validated | Source truth-only |
|---|---:|---:|---:|
| ORIGINAL_SAFE | 4 | 3 | 1 |
| PATCHED_SAFE | 0 | 0 | 0 |
| SYNTHETIC_SAFE | 0 | 0 | 0 |

| Control | Family | Доказанное свойство |
|---|---|---|
| JS-SAFE-AUTHZ-001 | authorization | Cross-user address GET denied при работающем owner GET |
| JS-SAFE-AUTHZ-002 | authorization | Cross-user card GET denied при работающем owner GET |
| JS-SAFE-DATA-001 | sensitive_data | List/item GET маскируют fixture card number до последних четырёх цифр |
| JS-SAFE-SQL-001 | sql_injection | Конкретный address lookup передаёт id как ORM where value, а не как SQL text |

Последний control доказывает **конструкцию исходного выражения**, не runtime
отсутствие SQL injection и не безопасность всего endpoint. Его proof содержит
точное выражение, anchor и digest Sequelize model provenance; изменение выражения
или модели инвалидирует proof. Все четыре `agent_verifiable_now=false`:
это evaluator fixtures/source truth, существующие production capabilities их не проверяют.
Source-only control не получает runtime verdict.

Меньшее число вместо ~20 намеренно зафиксировано: готовых независимых property
oracles для большинства официальных snippets нет, а часть snippets не является
полным применимым production patch. Имя correct, отсутствие scanner finding,
модельный ответ и HTTP error без предпосылок не дают safe truth. Новые B-stage
capabilities и изменение уязвимого поведения upstream tests ради числа контролей
в A03 не выполнялись. Четыре записи нельзя трактовать как репрезентативный
negative corpus из двадцати или как доказательство безопасности Juice Shop.

## Проверка официального патча и excluded registry

`redirectChallenge_4_correct.ts` точно сопоставлен с исходным annotation window
после удаления только annotation comments. Операторский однострочный diff
меняет substring comparison на equality, проходит существующий strict Stage 1
diff review, digest checks и `git apply` исключительно в disposable snapshot.
Оригинал остаётся byte-identical. Diff и real stage Evidence сохранены.

В **двух отдельных patched cycles** prepare/build прошли; tests дали
**411 passed, 2 failed, 2 skipped** из 415 upstream tests. Падают
`insecurity.unit.test.ts:259` и `redirect.unit.test.ts:84`: они намеренно требуют
уязвимое substring-поведение. Startup/smoke/security assertions после failed tests
не запускались. Поэтому PATCHED_SAFE не опубликован; reason `build_failure`
в registry означает failed required build/test pipeline, подробность явно говорит
о tests failure. Cleanup и original integrity подтверждены в обоих cycles.

Из 35 official candidates один excluded после реальной попытки, 34 pending:

| Reason | Count |
|---|---:|
| cannot_prove_safe | 31 |
| correct_fix_not_applicable | 2 |
| source_mismatch | 1 |
| build_failure (required tests failed) | 1 |

Два SQL correct snippets содержат `LIKE '%:criteria%'`: quoted placeholder не
соответствует действующей строгой Stage 1 replacement/bind policy. Они не
объявлены рабочими безопасными патчами. Остальные pending требуют полного
source correspondence/apply/build/tests/availability/property proof. Pending и
excluded не входят в reviewed count. Ни один кандидат не удалён молча.

## Reset, identities и availability

Machine-readable contract: `controls/reset.yaml`, adapter `juice_node_v1`.
Каждый будущий case/run обязан получить **новый disposable контейнер**, свежую
копию target в tmpfs, новый процесс и internal network. Volumes, published ports,
external network, reused database/session state отсутствуют. DB пересоздаётся
существующим upstream startup; collections/filesystem берутся из свежей копии.
Build/tests networkless; startup/smoke используют существующую internal network.
Installed immutable fix image записан в Evidence, pull/install не производится.

Два real ORIGINAL cycles прошли prepare/build/tests/start/smoke через существующие
Validator/Executor/Evidence/audit bindings. В каждом upstream suite:
**413 passed, 2 skipped** из 415. Fixture assertions пакетно проверяют три свойства
при первоначальной подготовке каталога; это не три scored benchmark runs.
Будущий evaluator должен соблюдать case-per-container contract, а не переиспользовать
этот setup между независимыми benchmark cases.

Операторский fixture создаёт `owner` и `other_user` через fixed registration,
выполняет login и подтверждает server ID/email через whoami. Этот handler требует
token cookie; bearer alone недостаточно. Пароли генерируются OS CSPRNG внутри
disposable Node process, живут вместе с tokens только в памяти, не попадают в
repo, reports, stdout/stderr или LLM. Emails и искусственные объекты не секретны.
Admin identity не требуется.

Обе identity начинают с пустыми address/card lists. Создаются по одному объекту
каждого типа; attempted client UserId forgery перезаписывается server identity.
Owner item/list GET подтверждают существование и ownership. Затем cross-user
GET возвращает конкретный error response; после него обе identity проверяются
повторно, owner GET продолжает работать. Invalid-token GET проверяется отдельно.
Denial без успешного legitimate request/session/object не считается safe.
Маскировка проверяется в обоих owner list/item responses.

Перед bootstrap все challenges `solved=false`; sorted key/solved baseline одинаков
в двух cycles. Fixture objects сохраняются внутри опыта и отсутствуют при новом
bootstrap. Logical state сравнивается без random credentials/tokens/container IDs
и upstream seeded faker values. В конце existing close удаляет container/network,
операторский post-cleanup inventory проверяет их отсутствие, TemporaryDirectory
удаляет snapshot, Stage 1 manifest подтверждает неизменность исходника.

`evaluation/control_bootstrap.cjs` — fixed evaluator-owned setup/assertions,
исполняемые только внутри Docker. Это не registered capability и не model setup
command. Любая failed предпосылка даёт unavailable/inconclusive, никогда safe.

## Split, leakage и merge

Reviewed distribution: **1 development / 3 holdout**, без ручного переназначения.
Используется исключительно A01 `split_group`. Root-cause keys не зависят от
positive IDs. Pending redirect twin использует `juice-redirect-substring-allowlist`,
SQL twins — `juice-search-query-sql-interpolation`; одинаковый group даёт одинаковый
split. Для остальных annotation-derived provisional keys установлен
`reconciliation_required=true`: согласование belongs to A04, A02 здесь не редактируется.
Два owner controls относятся к разным object handlers и не дублируют vulnerable
basket handler; ORM construction и authorization — разные scoped properties.

Truth, types, expected outcomes, codefix answers и patch остаются evaluator-only.
Тесты вызывают реальный Scout с malicious inventory, проверяют exclusion codefixes
и отсутствие labels/annotations в captured prompt, а также real reasoning projection
с injected evaluator fields. Frozen SAST rules ограничены routes/login.ts,
routes/search.ts и server.ts. Production code не импортирует A03 modules.
Эта гарантия относится к frozen A01 producer path; произвольный внешний caller,
намеренно помещающий answer в `code_context`, не поддерживается этим контрактом.

## Воспроизведение и проверки

Нужны чистый pinned checkout и уже provisioned Stage 1 images. Target scripts
не выполняются на host. Discovery/validation только читают исходники.

```powershell
python -m evaluation.control_catalog discover
python -m evaluation.control_reset --output artifacts/a03-checks/original
python -m evaluation.control_reset --patch-redirect --output artifacts/a03-checks/patched
# Последняя команда ожидаемо завершится nonzero: required upstream tests failed.
python -m evaluation.control_review
python -m evaluation.control_catalog validate
python -m evaluation.benchmark_protocol
$env:CFT_AGENT_MODE='stub'
python -m pytest -q
python -m ruff check .
git diff --check
python -m app.main
```

Результаты финальных checks и preservation записаны в `artifacts/a03-checks/`.
Финально: **43 A03 tests**; целевой набор A01/A02/A03/Stage2 и Stage1 regression —
**223 passed, 2 skipped**. Полный backend — **771 passed, 25 skipped, 2 известные
Windows failures**, без новых failures. Оставшиеся failures:
`test_trusted_docker_root_translation_is_explicit` и
`test_provenance_reaches_report_and_public_api_without_host_path`.
25 platform/opt-in skips: 16 Docker/image integration, 8 symlink, 1 POSIX limits.
Ruff, `git diff --check`, `python -m app.main` в stub mode, A01 protocol CLI,
A02 catalog CLI и A03 catalog CLI проходят. Все 164 historical v1 artifacts
byte-identical, три historical seals валидны.
A03 tests покрывают deterministic discovery, metadata/source/digest bindings,
disposable apply и exceptional cleanup, все runtime fail-closed gates, реальные
fresh reset proofs, leakage, происхождение/split, excluded patch и A01/v1 lock.
Windows sandbox блокирует ancestor reads в некоторых source fixtures, поэтому
финальный suite выполнен с обычным host filesystem доступом. Известная UNC
permission failure там не воспроизводится; две оставшиеся старые Windows failures
в `tests/test_finding_identity.py` не исправлялись. Новых failures нет.

Frontend и полный real Stage 1 E2E не запускались: production workspace/runtime/
patch apply/cleanup не изменены. Вместо этого использованы реальные existing stages
и релевантные regression tests. Historical v1 seal validation и A01 locked baseline
сохраняются. A03 не вычисляет benchmark metrics.
