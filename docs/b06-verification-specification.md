# B06: спецификация runtime-проверок Juice Shop

Версия протокола: `cft.b06.verification.v1`  
Дата фиксации: 14 октября 2026 года  
Основа: Juice Shop `v20.2.0`, commit `5658473cf8814459bf89000ce373b20ed0b4eb37`.

## Назначение

B06 добавляет ограниченные runtime-проверки для трёх DEV-категорий из A08:

| Случай | Claim | Статус перед runtime-приёмкой |
| --- | --- | --- |
| `JS-AUTH-001` | Аутентифицированный пользователь может сменить собственный пароль, не предъявив текущий пароль | Кандидат подтверждён исходником; runtime ещё не проверен |
| `JS-REDIRECT-001` | `/redirect` выдаёт `Location` на неразрешённое назначение из-за проверки allowlist через `includes` | Кандидат подтверждён исходником; runtime ещё не проверен |
| `JS-CODE-001` | Контролируемое значение исполняется в username-пути профиля | Runtime-проверка требует отдельного feasibility gate; наличие `eval` в исходнике недостаточно |

Эта спецификация определяет, какие факты могут привести к runtime verdict. Она не
меняет A04/A08, их замороженные профили и результаты. Preflight B06 является
инвентаризацией исходника и конфигурации; он не запускает приложение и не выдаёт
метрики.

## Архитектурная граница

Все активные операции идут по существующему пути:

```text
операторский finding и route binding
→ ActionProposal
→ Validator
→ зарегистрированная capability Executor
→ изолированный Docker runtime
→ сохранённые наблюдения
→ детерминированный Evidence interpreter
→ FinalReport
```

Модель выбирает только уже подготовленный application-owned candidate. Она не
задаёт URL, host, credentials, команды, fixture ID, reset, роль или HTTP-граф.
Ни одна новая проверка не обходит Validator/Executor и не расширяет target scope.

Существующие `Finding`, `ActionProposal`, `AgentState`, `Evidence` и
`VerificationBinding` остаются общими контрактами. Специфические наблюдения B06
добавляются типизированно в `schemas/b06_verification.py` и связываются с
обычными approval, execution и audit записями.

## Статические основания для claim

### Смена пароля

Операторская привязка включает `GET /rest/user/change-password`, обработчик
`routes/changePassword.ts` и его регистрацию в `server.ts`. Проверка должна
изолировать один эффект: уже аутентифицированный пользователь меняет собственный
пароль без значения `current`.

Успешный HTTP-ответ не подтверждает смену пароля. Нужен независимый вход с новым
паролем, отказ входа со старым и подтверждение серверной личности. До probe должны
успешно пройти вход, проверка личности, смена с правильным текущим паролем и
отрицательный контроль с неправильным текущим паролем. Анонимный запрос обязан
быть отклонён. Испытания выполняются на двух независимых fixture generations.

Результат относится только к повторной проверке личности при смене собственного
пароля. Он сам по себе не доказывает вход без пароля, доступ к чужому аккаунту,
повышение привилегий или обход второго фактора.

### Перенаправление

Операторская привязка включает `GET /redirect`, `routes/redirect.ts` и helper
`lib/insecurity.ts`. Проверяется реальный status и заголовок `Location`.

Positive control использует точное назначение, уже разрешённое исходным приложением.
Probe использует отдельное операторское назначение, которое удовлетворяет текущей
проверке подстроки, но после разбора URL ведёт на закреплённый локальный sink.
Negative control использует назначение без разрешённой подстроки. Все три значения
закрепляются в operator registry; модель получает только идентификаторы.

Клиент не следует redirect, не разрешает DNS имени из `Location`, не использует
внешний proxy и не открывает внешние адреса. Контроль проверяет только фактически
выданный заголовок. Неоднозначный, повторный, усечённый или отсутствующий
`Location` даёт `inconclusive`. Любое посещение sink отменяет положительный вывод.

### Выполнение кода

Проверка доступна только после проверки точного pinned image/config и фактической
ветви настоящего handler. В закреплённом исходнике `usernameXssChallenge` имеет
`disabledEnv: Docker`, а `config/default.yml` задаёт `safetyMode: auto`. Поэтому
до runtime-приёмки статус B06 — `runtime_gate_required`; нельзя считать
обнаруженный `eval` доказательством доступного исполнения.

Если gate подтвердит отключённую ветвь, результат этой категории —
`unsupported_runtime`, отображаемый как недостаточное Evidence. Он не считается
`rejected`, безопасным исходом или пропуском агентом доступной уязвимости. Нельзя
менять safety mode, определение Docker или настройки challenge ради получения
положительного контроля. Другая конфигурация, если она когда-либо будет разрешена,
получает отдельный target/profile и отдельные результаты.

## Verdict policy

Каждый runtime result вычисляется приложением из структурированных наблюдений.
Worker не передаёт свободную строку `confirmed` как достаточное доказательство.

| Verdict | Условия |
| --- | --- |
| `confirmed` | Источник и route однозначно связаны; controls успешны; эффект наблюдался на двух испытаниях; provenance, budgets, cleanup и записи согласованы |
| `rejected` | Проверяемая runtime-ветвь доступна; controls успешны; два испытания не показывают заявленный эффект и показывают ожидаемое безопасное поведение |
| `inconclusive` | Не сработал control, runtime недоступен, binding неоднозначен, испытание неполно, observations противоречивы, нарушен бюджет или cleanup не подтверждён |
| `unsupported_runtime` | До выполнения probe установлено, что заявленная runtime-ветвь отключена или capability не поддержана в закреплённом окружении |

`unsupported_runtime` — причина отсутствия runtime-вывода, а не новый terminal
status LangGraph. В обычном workflow она остаётся `inconclusive` с отдельным
reason code; технический сбой также не становится security verdict.

## Независимость и сброс

Redirect stateless для пользователя, но каждый trial всё равно получает отдельные
exchange IDs и полный набор controls. Интеграционная приёмка повторяет сценарий в
новой disposable generation.

Password change изменяет состояние. Каждый trial запускается на отдельной generation
со свежими customer identities и credentials. Обе generation подготавливаются до
approval; одно фиксированное действие явно одобряет весь двухtrial-протокол.
В digest входят оба generation ID, source/profile и runtime session. После
исполнения пара закрывается; повтор или замена generation требует нового approval.
Один успешный trial недостаточен для общего `confirmed`.

Операторский B04 fixture не считается автоматически частью канонического runtime.
Нужен явный доверенный lifecycle bridge: тот же pinned target instance для
controls и probe, привязанные к нему source/runtime digests и generation. Нельзя
подставить B04 `AccessFixtureContext` в B06 только заменой идентификаторов.

## Верхние границы протокола

| Фаза | Максимум |
| --- | ---: |
| Redirect: controls, два trials, один read-only retry | 8 HTTP exchanges |
| Auth: один полный trial | 17 HTTP exchanges |
| Auth: два trials и один read-only retry | 35 HTTP exchanges |
| B04 подготовка на одну generation | 64 HTTP exchanges |
| B04 controls на одну generation | 32 HTTP exchanges |
| Socket timeout | 3 секунды |
| Активный trial | 20 секунд |
| Размер request/response | 4 KiB / 64 KiB |

Полная верхняя граница auth при двух подготовках и двух отдельных control-сериях:
`2 × 64 + 2 × 32 + 35 = 227 HTTP exchanges`. Setup, readiness, reset и cleanup
учитываются отдельно. Только один ограниченный read-only запрос может быть
повторён; изменяющий запрос смены пароля при timeout не повторяется.

Усечение данных, timeout, неполная запись, неизвестный статус или превышение
бюджета исключают бинарный verdict. Ошибка cleanup блокирует следующую generation.
Удаляются только ресурсы с меткой конкретной B06 generation.

## Секреты и публикуемые данные

Пароли и токены создаются fixture и остаются внутри worker private tmpfs. Они не
передаются в argv, модель, AgentState, JSON/JSONL audit, telemetry, UI или
публикуемые артефакты. Не сохраняются URL с query, Authorization, Cookie,
Set-Cookie или полные тела login/password-change. Внешний результат содержит только
логические actor IDs, статусы, digest/route binding и минимальные факты.

## Definition of Done

B06 можно закрыть только после всех пунктов:

1. Новый B06 profile и source/helper inventory закреплены отдельно от A01–A08.
2. Validator и Executor повторно проверяют route, source/map/profile/runtime и
   fixture bindings; мутация или устаревшая generation отклоняется.
3. Redirect проходит два trials на исходном target, корректный positive control,
   negative control и safe patched control; ни один redirect не посещается.
4. Auth проходит два независимых trials; оба входа, server identity, controls,
   password readback, reset и cleanup связаны с сохранёнными записями.
5. Code evaluation имеет runtime gate с зафиксированными image/config фактами;
   если ветвь недоступна, отчёт объясняет `unsupported_runtime` без probe.
6. Interpreter пересчитывает verdict из observations, связывает их с approval и
   persisted execution/audit. Недостаточные данные остаются `inconclusive`.
7. Счётчик exchanges сходится с ledger и лимитами; секретов нет в экспортируемых
   файлах.
8. Реальная Docker-приёмка, safe controls, fault handling, cleanup и неизменность
   исходного pinned target подтверждены в отдельном sealed output.
9. Итоговый отчёт отдельно указывает поддержанные категории, ограничения и
   неподдержанный runtime. Не допускается обобщать вывод за пределы проверенного
   claim.

Результаты runtime-приёмки и ограничения публикуются в отдельном B06 runtime report.

## Read-only preflight

Команда `python3 -m app.b06_preflight --output artifacts/b06-preflight-2026-10-14-01`
проверяет чистоту и закреплённый commit исходного checkout, source anchors и
default-конфигурацию challenge. Она не запускает Docker или target code и не
делает HTTP-запросов. Выходной `preflight.json` фиксирует только статические
основания, а `seal.json` — его digest. Статус `static_preflight_complete` означает
успешную инвентаризацию, а не runtime acceptance или найденную уязвимость.
