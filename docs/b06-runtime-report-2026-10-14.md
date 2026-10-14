# B06: результат реализации и runtime-проверок

Дата: 14 октября 2026 года. Ветка: `codex/b06-verification`.

B06 выполнена для двух заявленных runtime-семейств: перенаправление на
неразрешённое назначение и смена собственного пароля без повторной проверки
текущего пароля. Code evaluation в закреплённой Docker-конфигурации не заявлена
как поддержанная capability: её ветвь действительно отключена приложением.

## Что работает

`targets/juice-b06-verification.yaml` и `policies/b06.yaml` являются отдельным
операторским профилем. Историческая `policies/default.yaml`, A01–A08 profiles,
locks и прежние результаты сохранены.

Pipeline принимает обычные Finding из SAST/Scout или сохранённого JSON. Уникальная
привязка B01 сопоставляет исходник с зарегистрированным handler. Для B06
операторский lifecycle подготавливает две независимые Docker generations и
передаёт приложению только публичную привязку. Модель выбирает candidate;
Validator, Executor, Evidence interpreter и FinalReport используют существующий
канонический workflow.

Approval покрывает полную пару generation ID, snapshot, профиль, service,
endpoint и параметры. Обе лаборатории создаются до approval. После выполнения
пара закрывается; replay action, смена generation или source mismatch блокируются.
Это конкретизация плана: вместо агрегирования двух разных action после reset
одобряется заранее ограниченный двухtrial-протокол.

Auth переиспользует фиксированную B04 подготовку двух customer identities и
владения объектами. Credentials сохраняются исключительно в worker private
tmpfs. Личность доказывается server whoami, смена пароля — независимыми login с
новым и старым паролем. Отдельный B-owned объект остаётся неизменным и доступным
своему владельцу. HTTP 200 без этих доказательств не даёт confirmed.

Redirect проверяет только настоящий status/Location. Клиент не следует
перенаправлениям и не выполняет DNS назначения. Локальный sink независимо считает
входящие обращения. Он не получил ни одного запроса во всех испытаниях. Positive
control использует уже разрешённый внешний URL только как значение заголовка.

## Реальная Docker-приёмка

Target: Juice Shop `v20.2.0`, commit
`5658473cf8814459bf89000ce373b20ed0b4eb37`.

Image:
`bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`.

| Capability | Исходный target | Безопасный control | Испытания |
| --- | --- | --- | --- |
| `verify_redirect_destination` | confirmed | rejected | По две независимые generations для каждого варианта |
| `verify_auth_reauthentication` | confirmed | rejected | По две независимые generations для каждого варианта |

Все четыре сценария прошли через Validator и SafeExecutor. Execution/audit,
source binding, preparation, ledger и cleanup сохранены. Все восемь generations
удалены с проверкой отсутствия принадлежащих им containers/networks. Исходный Git
checkout остался чистым и byte-identical закреплённому tree.

Safe controls — отдельные операторские snapshots: exact equality allowlist и
обязательный правильный текущий пароль. Статические TS и соответствующие compiled
JS изменения зафиксированы отдельно; исходное приложение и frozen benchmark не
изменялись.

Auth: 39 setup HTTP exchanges и 17 active exchanges на generation; для одного
двухtrial-сценария — 112 exchanges плюс отдельно записанные readiness requests.
Максимум без отдельной повторной B04 control-серии — `2 × 64 + 2 × 17 = 162`.
Redirect: по 3 HTTP exchanges на generation, всего 6. Чтение внутреннего счётчика
sink не делает дополнительного HTTP-запроса. Socket limit — 3 секунды, active
trial limit — 20 секунд. Requests и responses ограничены 4 KiB и 64 KiB.

## Code evaluation

В работающем закреплённом image наблюдалось:

```json
{"docker":true,"safety_mode":"auto","enabled":false,"disabledBecause":"Docker"}
```

`usernameXssChallenge` отключена этой конфигурацией. Status:
`unsupported_runtime`; marker не исполнялся, capability не зарегистрирована.
В pipeline такая находка получает inconclusive с объяснением ограничения.
Это не rejected и не безопасный результат проверки доступной уязвимости.

## Проверки реализации

Полный pytest: **1064 passed, 18 skipped**. Добавлены 22 необходимых B06 теста,
включая пропавшие controls, неоднозначные credentials, подмену личности/объекта,
ошибку cleanup, неполный ledger, stale fixture, изменение source/ActionProposal,
отсутствующий audit и запрещённые поля. Platform/Docker opt-in skips остались;
реальная B06 Docker-приёмка выполнена отдельно, не выдаётся за skipped тесты.

Ruff проходит для проекта с исключением посторонних локальных `tmp/`, `ultra-os/`
и `output/`. Эти файлы не входят в B06. Детерминированный `python -m app.main`
проверяется отдельно при публикации.

Обычный `app.pipeline_run` в stub-режиме: две подтверждённые runtime-находки и
одна неподдержанная code-evaluation находка. CI/CD Gate FAIL с exit code 1 означает
завершённый анализ с подтверждёнными проблемами; exit 2 означал бы технический сбой.

Два offline replay из одного sealed пакета совпали побайтно. Новых Docker/LLM
вызовов при replay не было. Replay проверяет membership seal, схему результата,
generation/source/action binding и соответствующий persistent audit перед
пересчётом verdict.

## Команды и артефакты

Создать новый runtime acceptance:

```bash
python -m app.b06_acceptance --output artifacts/b06-acceptance-new
```

Запустить обычный pipeline с B06 profile и собственными source-bound findings:

```bash
python -m app.pipeline_run --profile targets/juice-b06-verification.yaml \
  --findings path/to/normalized-findings.json --agent-mode stub \
  --output-dir artifacts/b06-pipeline-new --max-iterations 1
```

Offline replay:

```bash
python -m app.b06_replay --input path/to/extracted/acceptance \
  --output artifacts/b06-replay-new.json
```

Итоговые данные:

- `artifacts/b06-acceptance-2026-10-14-complete/`: sealed original/safe scenarios.
- `artifacts/b06-pipeline-2026-10-14-release/`: обычный graph, FinalReports и Gate.
- `artifacts/b06-summary-2026-10-14-release/`: совпадающие offline replay.
- `artifacts/b06-handoff-2026-10-14.zip` и `.zip.sha256`: переносимый пакет.

В архиве есть собственный manifest SHA-256, audit, execution, source/control
snapshots, runtime facts, ledger и документация. Environments, node_modules,
runtime credentials и Docker private state туда не включаются.

## Ограничения вывода

Это приёмка конкретных capabilities, а не новая серия метрик обнаружения по
полному Juice Shop benchmark. Она не показывает прирост Recall сама по себе.
B09 должен отдельно измерить обнаружение и подтверждение на сопоставимом наборе.

Измерялся pinned локальный Docker target. Связь source/image является операторской
привязкой и не является независимой binary attestation. Safe-control snapshots
учитываются отдельно от исходных benchmark cases. Живой LLM в этом этапе не
вызывался: выбор кандидата проходит тот же application-owned интерфейс.

Новый профиль включается явно в CLI. Универсальная подготовка credentials для
произвольных загружаемых проектов, включение отключённой code boundary и новая
серия benchmark runs не входят в B06.
