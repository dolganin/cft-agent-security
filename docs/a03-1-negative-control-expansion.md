# A03.1 — расширение negative control corpus

Дата: 11 октября 2026. Target: Juice Shop v20.2.0,
`5658473cf8814459bf89000ce373b20ed0b4eb37`.
Результат: **4 → 14 reviewed controls, 14 независимых groups**.
Это truth preparation; precision/FPR, scored runs и A04 freeze не выполнялись.

## Исходное состояние сохранено

Четыре A03 records, их Evidence, reset, schemas, implementation и tests сохранены
byte-identical. Не переписаны A01 protocol/helper, A02 positives, v1 или production
Pentester. `expansion/frozen-inputs.yaml` фиксирует 51 существующий input.
Для protocol.lock.json отдельно допускается только известная LF-эквивалентная
форма исходного CRLF JSON; сам исходный lock не изменён, A01 preflight обязателен.
Raw preservation checks дополнительно сравнивают первоначальные bytes.
Ошибок существующих четырёх controls не обнаружено (`existing_control_issue=[]`).

Новые записи находятся в `controls/expansion/controls.reviewed.yaml`; старый
`controls/controls.reviewed.yaml` намеренно продолжает содержать четыре frozen
records. Расширенный validator объединяет два каталога только для проверки
truth/reconciliation. Scorer/matcher/producer integration не добавлена.

## Количества и свойства

| Type | Before | Added | Total | Juice runtime | Source-only | Synthetic behaviour |
|---|---:|---:|---:|---:|---:|---:|
| ORIGINAL_SAFE | 4 | 4 | 8 | 3 | 5 | 0 |
| PATCHED_SAFE | 0 | 2 | 2 | 2 | 0 | 0 |
| SYNTHETIC_SAFE | 0 | 4 | 4 | 0 | 0 | 4 |
| Total | 4 | 10 | 14 | 5 | 5 | 4 |

Таким образом, девять controls имеют execution-backed assertions, из них только
пять проверены против работающего Juice Shop. Четыре synthetic controls проверены
как отдельные функции в свежих Docker processes. Их нельзя выдавать за Juice Shop
runtime proof. Ни один source-only control не получает runtime REJECTED;
все новые records имеют `runtime_verdict=null`, `agent_verifiable_now=false`.

Новые ORIGINAL_SAFE были рассмотрены первыми:

| ID | Family | Узкое source property |
|---|---|---|
| JS-SAFE-AUTH-101 | authentication | 2FA disable rejects password differing from authenticated cache hash before clearing TOTP secret |
| JS-SAFE-FILE-101 | file-validation | Upload type is detected from bytes; unknown/non-image branches exit before write |
| JS-SAFE-PATH-101 | path-traversal | Upload filename expression uses cached server ID and detected extension, not client filename |
| JS-SAFE-BIZ-101 | business-logic | Existing stock row's upper-bound branch rejects quantities exceeding stock |

Oracles проверяют точные branch bodies, порядок операций, полный source digest и
function anchor. Это доказательства конкретной конструкции, не безопасности
endpoint. Последний control не исправляет отрицательные quantities: они остаются
vulnerable. Password gate не делает MD5 сильным и не доказывает database reauthentication
или свежесть cached password. Content-type gate не доказывает,
что каждый принятый image harmless. Filename property не моделирует corrupted
authentication cache или symlinks. Все ограничения входят в records.

Два PATCHED_SAFE:

| ID | A02 twin | Property oracle |
|---|---|---|
| JS-SAFE-REDIRECT-101 | JS-REDIRECT-001 | Exact URL gives 302/expected Location; four unapproved variants give 406/no Location; valid request and search still succeed |
| JS-SAFE-NOSQL-101 | JS-NOSQL-001 | Existing own fixture review changes once for literal ID; object/number/null IDs return 400 without changing reviews; identity and valid update still work |

NoSQL control относится только к selector operator injection. Он не объявляет
исправленной отсутствующую review ownership authorization (JS-BOLA-003).

Четыре SYNTHETIC_SAFE добавлены после triage оригинала и официальных fixes:

| ID | A02 twin | Fixture property |
|---|---|---|
| JS-SAFE-XSS-101 | JS-XSS-001 | HTML text escaped inside fixed paragraph, controlled script text cannot form an element |
| JS-SAFE-PATH-102 | JS-PATH-001 | Normalized archive-name destination remains under fixed root; escape/absolute/backslash/NUL denied |
| JS-SAFE-XXE-101 | JS-XXE-001 | Small DTD-free XML subset; DOCTYPE/ENTITY rejected before parsing |
| JS-SAFE-CODE-101 | JS-CODE-001 | Expression-looking profile name remains literal string; no expression evaluation |

Fixture application source и evaluator assertion source физически разделены:
`synthetic/fixtures.py` и `synthetic/tests/check_fixture.py`. Source reader исключает
tests; assertion labels/expected answers не являются application source. Есть
positive, negative и post-check assertions. Fixture исполняется только в Docker:
immutable installed Python image, network=none, read-only mount/root, user 1000,
cap-drop, no-new-privileges, CPU/memory/process limits. После двух запусков containers
удалены. Credentials/external network/host target execution отсутствуют.

Итого **12 families**: authorization, sensitive_data, sql_injection, authentication,
file-validation, path-traversal, business-logic, open-redirect, nosql-injection, xss,
xml-external-entities, code-evaluation. Legacy spelling первых A03 families сохранён.

## Official fix triage и dispositions

Прочитаны generated index, correct files, metadata, annotation source и tests.
Cheap static triage выбрал **6 из 35** candidates, а не последовательный прогон всех
pending. В `expansion/triage.yaml` каждый ещё `truth_validated=false`:

| Candidate | Result |
|---|---|
| redirectChallenge_4 | Два real complete cycles, PATCHED_SAFE accepted |
| noSqlReviewsChallenge_3 | Два real complete cycles, PATCHED_SAFE accepted |
| registerAdminChallenge_3 | Pending: send.before mutates context after database creation; persisted role binding не доказан |
| exposedMetricsChallenge_3 | Excluded: official fix invokes absent isAdmin helper; coverage of both metrics registrations не доказана |
| localXssChallenge_2 | Pending: current Stage1 adapter copies prebaked frontend-dist, не собирает modified frontend |
| restfulXssChallenge_1 | Pending: требуется rebuilt frontend и независимый browser/render oracle |

Финальный registry охватывает все 35 IDs: **2 reviewed, 1 excluded, 32 pending**.
Каждая запись содержит previous A03 disposition; исходный excluded.yaml не изменён.
Для 29 unselected candidates сохранён status pending/not_selected_after_static_triage.
Старые причины, включая две quoted SQL placeholders и source mismatch, не потеряны:
они находятся в embedded previous_disposition. Correct filename не предоставляет truth.

Только redirect и NoSQL были реально прогнаны через patch pipeline. Подготовительные
trial attempts останавливались на ошибке evaluator test-summary parsing и не
получали safe verdict. Ошибка исправлена, fail-closed classifier протестирован;
сырые Executor records/audit и сохранённый redirect history остаются в Evidence.
Финальные assertions выполнялись в новых containers, не ретроспективно добавлялись
к failed attempts. Это технические trials, не benchmark measurements.

## Case-specific vulnerable test expectations

Redirect original A03 result остаётся excluded в frozen input. A03.1 применяет
новую явно разрешённую case-specific classification, сохраняя исходные test results:

1. `test/server/insecurity.unit.test.ts:258–260`,
   `returns true for URLs containing allowed URLs`: ожидает true для appended path,
   что противоречит exact equality allowlist.
2. `test/server/redirect.unit.test.ts:77–85`,
   `tricking the allowlist should solve "redirectChallenge"`: ожидает solved от
   off-domain URL, содержащего allowlisted URL.

Anchors, source digests, names и объяснения записаны в report.test_provenance.
Оба failures классифицированы `vulnerable_behavior_expectation`; остальные
**411 tests passed, 2 skipped** из 415. Classifier принимает ровно эти два leaf
failures, только для redirect, с полным pinned suite summary и без cancellation.
Functional/unknown/additional failures, empty suite и другой candidate блокируют
acceptance. Все 415 tests реально запускаются: test filtering/blanket ignore нет.
Persisted execution status для tests остаётся `failed/exit=1`; evaluator acceptance
с classification не превращает его в successful Executor result.

NoSQL suite целиком проходит: **413 passed, 2 skipped** из 415, exceptions отсутствуют.
В обоих candidates build/start/smoke обязательны и проходят; независимые HTTP
oracles дают positive/negative/post-check proof. Patch exact correspondence,
single-source scope и Stage1 strict diff review проверены. NoSQL переносит official
type guard/removal of multi option, сохраняя upstream challenge instrumentation.
Официальный fix сам по себе не используется как oracle.

## Reset, integrity, leakage и reconciliation

Существующий `juice-fresh-stage1-v1` reset не изменён. Case-specific review user,
review object и synthetic process contract описаны отдельно в
`expansion/reset-additions.yaml`, поверх прежнего fresh-container core.
Оба patches применяются
существующим Stage1 apply engine только в disposable snapshot; контейнер использует
fresh tmpfs target/DB/session state, no volumes, internal target network. Стадии
`fix_target_stage` проходят прежние Validator, Executor, persistent Evidence и audit.
Каждый candidate проверен в двух containers. Cleanup доказывает отсутствие container
и network, удаление snapshot и исходный manifest digest.

NoSQL fixture создаёт отдельного пользователя, пароль OS CSPRNG и token остаются
только в памяти. Whoami подтверждает id/email до и после negative request. Review
создан и найден до assertion; legitimate update работает до/после запрета. Redirect
не следует Location и не обращается к внешним destinations. HTTP error, missing
resource, failed identity, timeout, build/start/availability/cleanup failure не дают safe.

`controls/reconciliation.yaml` включает все 14 controls. **6 direct safe twins**
используют exact A02 IDs, root_cause_key, independence_group и split. **8 independent
safe properties** явно не имеют direct positive twin. Validator отказывает при любом
group/root/split mismatch, не переписывая A02. DEV/HOLDOUT назначены helper A01:
**8 development / 6 holdout**. Final A04 review/freeze остаётся отдельной работой.

Truth, patch answers и assertion outcomes остаются evaluator-only. Production
imports/registry/Agent behavior не изменены. Existing A03 captured-prompt leakage
tests проходят; новые tests дополнительно проверяют исключение synthetic assertion
source и отсутствие A03.1 imports в production. Ни один новый oracle не registered
как Agent/Executor security capability.

## Проверки и воспроизведение

Нужны pinned clean checkout и уже installed Stage1 fix/Python images; pull/install нет.

```powershell
python -m evaluation.control_expansion_runtime redirect
python -m evaluation.control_expansion_runtime nosql
python -m evaluation.control_expansion_runtime synthetic
python -m evaluation.control_expansion publish
python -m evaluation.control_expansion validate
python -m evaluation.benchmark_protocol
$env:CFT_AGENT_MODE='stub'
python -m pytest -q
python -m ruff check .
git diff --check
python -m app.main
```

Publication детерминирована относительно frozen source и записанного Evidence;
UUID/passwords/time реального runtime не выдаются за deterministic logical state.
Evidence-backed corpus slices остаются раздельными. До следующих стадий нужен
independent review в A04; расширение не доказывает production generalization.
SSRF/rate-limiting и другие недостающие families не заполнены фиктивными controls.
Path fixture моделирует нормализацию строк, не filesystem symlinks; XML fixture —
ограниченный XML subset; HTML fixture — text context, не все browser contexts.
Новых больших frameworks, scanners, provider calls или scored runs нет.

Финальные results и preservation: `artifacts/a03-1-checks/`.

- A03.1 tests: **40 passed**.
- Полный целевой набор A01/A02/A03/A03.1/Stage2 и Stage1 regression внутри финального
  backend run: **263 passed, 2 skipped**.
- Полный backend: **811 passed, 25 skipped**, только две исходные Windows failures:
  `test_trusted_docker_root_translation_is_explicit` и
  `test_provenance_reaches_report_and_public_api_without_host_path`.
- 25 platform/opt-in skips: 16 Docker/image integration, 8 symlink, 1 POSIX limits.
- A01 preflight, A03.1 validation, Ruff, `git diff --check`, `python -m app.main`
  в stub mode проходят. Target remains pinned and clean.
- Raw bytes всех 44 первоначально сохранённых A03/A02 файлов неизменны; A01/v1
  inputs сохранены, все 164 historical artifacts совпадают, три seals валидны.
- Existing-control issues отсутствуют. Original/patch fixtures после cleanup
  отсутствуют, original checkout неизменён. Source-only описания и минимальные
  synthetic fixtures дополнительно проверены после финального уточнения их scope.

A03.1 COMPLETE. К A04 переход не выполнялся.
