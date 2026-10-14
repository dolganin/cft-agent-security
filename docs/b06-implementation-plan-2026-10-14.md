# B06. Подробный план реализации доказательных runtime-проверок

Дата: 14 октября 2026. Основа: `main`, коммит `560e2de`.
Статус документа: реализация B06 выполнена; актуальная техническая спецификация находится в `docs/b06-verification-specification.md`. Результаты проверок приведены в B06 runtime report.

Уточнение реализации: две независимые generations подготавливаются до approval и
явно связываются с одним фиксированным двухtrial-действием. Approval покрывает
оба generation ID; после исполнения повтор/замена требует новой пары и approval.
Это заменяет предложенное ниже агрегирование двух отдельных ActionProposal.

## 1. Какой результат должна дать задача

B06 расширяет возможности проверки уже найденных кандидатов. Для каждого
поддержанного случая агент должен получить воспроизводимое доказательство
конкретного эффекта на запущенном тестовом приложении либо обоснованный отказ
от вывода при недостаточных данных.

Основные семейства карточки:

1. Authentication: в текущем DEV-наборе приоритетна смена пароля без обязательной
   повторной проверки текущего пароля.
2. Open redirect: выдача приложением перенаправления на неразрешенное назначение.
3. Code evaluation: только если соответствующая граница исполнения действительно
   доступна в заявленном окружении и допускает строго ограниченную проверку.

Для каждого включенного семейства нужны:

- точная проверяемая гипотеза и операторская привязка к исходнику/маршруту;
- положительный контроль работоспособности;
- отдельный отрицательный контроль;
- два различимых испытания с указанным reset;
- ограниченный, полностью учитываемый бюджет;
- структурированные наблюдения и детерминированное решение;
- прохождение обычного Validator/Executor/Evidence workflow;
- реальная Docker-приемка на исходном и безопасном контрольном варианте;
- сохраненные артефакты и возможность пересмотреть вывод без повторного LLM-вызова.

Конечный сценарий:

```text
Finding из SAST или Scout
  -> уникальная source/route-привязка B01
  -> проверка поддерживаемости и готовности fixture
  -> операторский candidate
  -> ActionProposal
  -> Validator
  -> зарегистрированная capability в Executor
  -> фиксированные controls и probe
  -> сохраненные execution/audit observations
  -> строгая проверка Evidence
  -> confirmed / rejected / inconclusive
  -> FinalReport с точным объяснением результата
```

## 2. Что уже существует и на что опираться

| Компонент | Текущее состояние | Использование в B06 |
| --- | --- | --- |
| B01 | AST-привязка source -> handler -> route, source/map digests, повторная проверка в Validator и Executor | Сохранить и расширить перечисление разрешенных capabilities/checks |
| B04 | Два customer-пользователя, свои объекты, серверный whoami, controls, приватные токены, destroy/reset | Переиспользовать внутреннюю механику подготовки и доказательства личности |
| B02 | Закрепленный SAST-профиль, новые кандидаты, отдельные detection-метрики | Поставщик кандидатов; его alerts не являются runtime Evidence |
| B03 | Самостоятельное чтение кода с provenance и ограничениями | Второй поставщик кандидатов, без изменения разрешений |
| R01 | Проектные контракты auth/redirect/code и synthetic-примеры | Основа требований, но не готовые зарегистрированные проверки |
| Executor | Registry, approval digest, Docker, network policy, сохранение execution/audit | Единственная граница запуска новых активных проверок |
| Evidence | Канонические модели, interpreter и guard | Новые специализированные строгие results внутри существующего Evidence |

Файлы, которые необходимо учитывать при реализации:

- `agent/verification.py`, `agent/model.py`, `agent/llm_model.py`, `agent/nodes.py`;
- `security/verification_binding.py`, `schemas/verification_binding.py`;
- `schemas/action.py`, `schemas/evidence.py`, `schemas/security_tools.py`;
- `validator/validator.py`, `executor/executor.py`, `executor/worker.py`;
- `executor/access_fixture.py`, `executor/access_fixture_worker.py`;
- `evidence/interpreter.py`, `evidence/guard.py`, `tools/contracts.py`;
- `targets/juice-verification.yaml`, `targets/juice-access-fixture.yaml`;
- `docs/r01-verification-specifications.md` и `contracts/examples/r01/`.

### Ограничения существующих компонентов

1. `VerificationRoute.tool` и `check` сейчас допускают только прежние SQL и
   directory-проверки. Добавления названия в prompt недостаточно.
2. `validate_action_binding()` сравнивает точные параметры действия. Новые
   fixture-данные нельзя произвольно добавить в parameters и обойти это сравнение.
3. `AccessFixtureLab` жестко привязан к B04 profile ID, runtime type и endpoint `/`.
   Это отдельный lab, а не готовый runtime canonical pipeline.
4. Публичный `AccessFixtureContext` содержит B04-specific IDs. Нельзя выдать его
   за контекст другого target посредством неподтвержденной замены ID.
5. B04 сохраняет в приватном worker state токен и серверную личность, но исходный
   пароль после подготовки не сохраняет. Для password-change/readback B06 нужен
   отдельный приватный credential state.
6. B04 source inventory содержит восемь файлов. В нем нет всех исходников B06;
   его digest недостаточен для новых обработчиков.
7. Текущий общий `BoundedVerificationResult` не доказывает автоматически наличие
   всех controls, идентичность пользователя и независимость испытаний.

## 3. Точное покрытие по A08 и проверенному исходнику

| DEV-случай | Источник | Что реально проверять | Исходная проблема |
| --- | --- | --- | --- |
| `JS-AUTH-001` | `routes/changePassword.ts`, регистрация в `server.ts` | Пропуск обязательной reauthentication при смене собственного пароля | В A08 отсутствовал кандидат; runtime-случай допустим |
| `JS-REDIRECT-001` | `routes/redirect.ts`, `lib/insecurity.ts` | Неавторизованное назначение в настоящем `Location` | Кандидат существовал, Evidence было недостаточно |
| `JS-CODE-001` | `routes/updateUserProfile.ts`, `routes/userProfile.ts` | Вычисление контролируемого значения на конкретной evaluation boundary | В A08 `runtime_eligible=false`; необходимо подтвердить поддерживаемость |

### 3.1. Authentication здесь означает reauthentication

`changePassword()` сначала требует известного аутентифицированного пользователя,
а затем проверяет текущий пароль только при наличии соответствующего значения.
Следовательно, проверяемая гипотеза: «аутентифицированный пользователь может
изменить собственный пароль без требуемого повторного доказательства знания
текущего пароля».

Нельзя называть этот результат входом без пароля, доступом к чужому аккаунту,
получением admin-роли или обходом 2FA. B04 предоставляет двух customer-пользователей,
а не customer/admin. Общий authz bypass относится к другой гипотезе и не должен
подмешиваться в этот сценарий.

### 3.2. У redirect есть несовпадение с первоначальным R01

R01 описывает положительный контроль с разрешенным локальным назначением.
В текущем исходнике Juice Shop allowlist содержит внешние URL. Поменять allowlist
приложения ради красивого контроля нельзя.

Нужно выпустить отдельную версию B06 redirect-спецификации: положительный контроль
использует точное, уже разрешенное приложением значение, но проверка только
читает заголовок. Ни это назначение, ни probe sink не посещаются, DNS для них
не выполняется. Все значения назначений закрепляет оператор; модель получает IDs.
Контроль считается проверкой выдачи заголовка, а не доступности внешнего сайта.

### 3.3. Для code evaluation сначала обязательна проверка поддерживаемости

В исходнике `userProfile.ts` ветвь с `eval` зависит от
`isChallengeEnabled(usernameXssChallenge)`. Метаданные challenge исключают Docker,
а `getChallengeEnablementStatus()` учитывает environment и safety mode.
Наличие `eval` в тексте не означает, что этот код исполняется в закрепленном lab.

До реализации положительного probe нужно проверить точный image/config и
зафиксировать причину доступности или отключения ветви. Рабочее ожидание для
нынешнего benchmark runtime: `unsupported`, а не `rejected`.

Нельзя незаметно менять safety mode или защиту определения Docker. Если для
исследования потребуется отдельная конфигурация с иной доступностью challenge,
она оформляется отдельным target/profile и отдельными результатами. Ее результаты
не подставляются в метрики исходного benchmark.

## 4. Границы работы

Входит в B06:

- три отдельных паспорта поддерживаемости;
- рабочие auth-reauth и redirect проверки;
- code-evaluation capability только после прохождения feasibility gate;
- строгие результаты, controls, accounting, reset и интеграционная приемка;
- автоматический выбор подходящей проверки для привязанного Finding;
- сообщения пользователю о неподдержанной проверке и недостаточном Evidence.

Не входит:

- автоматическое исправление целевого кода;
- исправление BOLA и произвольных операций с чужими объектами из B05;
- общий каталог login/JWT/2FA/brute-force проверок;
- универсальный генератор payloads или произвольных HTTP-запросов;
- новый полный benchmark-прогон и итоговое измерение B09;
- изменение эталона A04, A06/A07/A08, скрытых меток или historical locks;
- включение отключенных challenge в исходном benchmark runtime.

## 5. Архитектурное решение: один проверенный lab для действия

Самый важный интеграционный шаг: preparation, identity, probe, runtime map и
source snapshot должны относиться к одному реально работающему экземпляру.

Нельзя подготовить пользователей в отдельном B04 target, затем выполнить действие
в target canonical pipeline и считать личности/objects общими.

### Предлагаемая схема

1. Создать отдельный `targets/juice-b06-verification.yaml`.
2. Выделить из B04 повторно используемую внутреннюю механику lifecycle/private
   worker. Публичные B04 profile и API сохранить совместимыми.
3. Операторский orchestration создает B06 lab, готовит accounts и публикует
   доверенный runtime descriptor того же target: instance/session ID, network,
   service endpoint inventory, source/profile/image digests, fixture generation.
4. Передать Executor только операторский handle/registry, а в AgentState только
   сериализуемые public facts и opaque IDs.
5. Новые probes выполняет зарегистрированная capability после approval.
   Provision/reset остаются операторскими операциями lifecycle.
6. Любая смена generation/instance требует новой привязки и approval.

Не добавлять флаг вида `skip_b04_validation=True`. Для нового профиля нужны
собственная строгая валидация и тесты, а не отключение существующих проверок.

### Два испытания и reset

- Redirect не меняет учетные данные. Два испытания могут идти в одной session
  при фиксированном reset состояния тестовой fixture и повторных controls.
  Сам capability затем повторяется целиком в другой независимой generation
  в интеграционной приемке.
- Password-change меняет состояние. Использовать свежую disposable generation
  для каждого основного испытания, чтобы не зависеть от старого JWT/user cache.
- Каждое испытание на новой generation проходит отдельный ActionProposal,
  Validator и Executor. Approval от первой session не переиспользуется.
- Итоговое подтверждение reauth собирается детерминированно из двух связанных
  persisted trial records. Первый успешный trial сам по себе недостаточен.
- Для итогового Evidence выбрать последний настоящий action ID, а связанные
  action/approval/execution refs и trial session IDs перечислить явно. Interpreter
  проверяет каждую связанную запись. Если это не укладывается в текущий Evidence
  guard, добавить узкий типизированный bundle, не переписывая историю действий.

## 6. Операторский профиль и привязки

Для каждого нового маршрута зафиксировать:

- `route_id`, `handler_id`, canonical family и точный claim;
- service, HTTP method и endpoint;
- tool/check и фиксированный режим;
- AST registration anchor;
- обработчик, caller/helper selectors;
- поддержку на конкретном image/config;
- fixture/reset adapter ID и версию контрольного протокола;
- network class и бюджеты.

Обязательные связи:

| Claim | Основной маршрут | Дополнительные операторские операции |
| --- | --- | --- |
| password reauthentication | `GET /rest/user/change-password` | Обычный login, whoami и owner-read контрольного объекта |
| open redirect | `GET /redirect` | Данные назначений и проверка счетчика local sink |
| code evaluation, если поддержан | Реальная boundary профиля пользователя | Фиксированная подготовка синтетического пользователя и инертного marker |

Control endpoints тоже входят в операторский scope. Их не нужно выдавать модели
как универсальные инструменты. Capability получает право только на свое заранее
перечисленное расписание операций.

B01 нужно расширить на новые tools/checks. Его проверки неоднозначности,
source/map snapshot, сдвига строк и повторной валидации сохраняются.
Для redirect Finding в `lib/insecurity.ts` требуется явная helper-связь с `/redirect`.

Привязку к fixture generation лучше вынести в отдельный application-owned
`FixtureExecutionBinding`, включенный в digest ActionProposal. Источник истины
для его проверки - доверенный registry lab, не модель и не переданный ею JSON.
Существующий `VerificationBinding` продолжает описывать связь source/route.

## 7. Контракты результатов

Предлагаемые новые общие модели в `schemas/b06_verification.py`:

- `FixtureExecutionBinding`: fixture/generation/trial/session и profile/source digests;
- `VerificationSupport`: supported/unsupported, фиксированный reason code, runtime scope;
- `VerificationExchange`: номер, тип control/probe/readback, operation ID,
  principal ID, статус, краткие проверяемые факты, расход бюджета;
- `AuthReauthenticationTrialResult`;
- `AuthReauthenticationResult`, связывающий два проверенных trials;
- `RedirectDestinationResult`;
- `CodeEvaluationResult`, только если поддерживаемость доказана.

Переиспользовать существующие общие модели Evidence и подходящие B04 nested types.
Не создавать компонент-локальную копию AgentState/ActionProposal/Evidence.

В специализированном результате обязательны:

- schema/protocol version, claim и capability ID;
- target, service, endpoint, source/map/profile digests;
- fixture ID, generation, sandbox session и ссылки на approved actions;
- список наблюдений по порядку с уникальными exchange IDs;
- раздельные положительный/отрицательный controls;
- фактические principal/effect/readback observations;
- два trial результата и их reset provenance;
- request/response/time accounting;
- flags truncation, timeout, unexpected redirect и cleanup;
- explanation и область, к которой относится вывод.

`controls_passed=true` без согласованных наблюдений недостаточно. Итоговый verdict
должен вычисляться из фактов и проверок связности, а не приниматься из stdout
как доверенная строка. Неизвестные поля и неверные комбинации отклоняются.

Публичные структуры не содержат пароли, токены, cookies, password hashes,
полные ответы с пользовательскими данными, полный URL с password query.

## 8. Redirect: первый вертикальный срез

Предлагаемое имя capability: `verify_redirect_destination`.

### 8.1. Фикстура

- Закрепленное разрешенное приложением значение для positive control.
- Отдельное явно запрещенное значение для negative control.
- Отдельное operator-owned probe destination, канонически соответствующее
  безопасному локальному sink.
- Связь каждого destination ID с неизменным тестовым значением в операторском
  registry. Свободных URL/hosts в ActionProposal нет.
- Local sink не является источником приватных данных и не имеет внешнего выхода.

### 8.2. Исполнение

1. Проверить fixture/source/session binding и оставшийся бюджет.
2. Выполнить positive control: получить настоящий redirect status и единственный
   корректный `Location` с ожидаемым approved destination.
3. Выполнить отдельный negative control: получить явный отказ либо разрешенную
   канонизацию, точно описанную протоколом.
4. Для trial 1 повторить allowed control и выполнить candidate probe.
5. Сбросить состояние тестовой fixture операторским adapter.
6. Для trial 2 повторить allowed control и probe.
7. Проверить cleanup и независимый счетчик sink: ни одного посещения.

HTTP-клиент не следует перенаправлениям, не использует host proxy и не выполняет
DNS-разрешение значений из `Location`. Разбор URI сам по себе не требует сети.
Неоднозначные/повторные/усеченные заголовки дают inconclusive.

### 8.3. Решение

- `confirmed`: controls прошли, два настоящих redirect-ответа указывают после
  однозначной канонизации на закрепленный неразрешенный sink, follow отсутствует.
- `rejected`: controls прошли, оба probe отклонены либо направлены только на
  разрешенный destination в рамках точной гипотезы.
- `inconclusive`: failed control, неизвестный Location, body reflection без
  перенаправления, timeout, source/session mismatch, посещение sink или cleanup error.

### 8.4. Проверка безопасного варианта

Использовать уже рассмотренный DEV patched-control redirect при возможности
переиспользования его существующего patch adapter. Проверка идет на отдельной
disposable snapshot с новым source digest и заново рассчитанной B01-привязкой.
Тот же probe должен дать `rejected`, положительный контроль должен работать.
Патч не вносится в исходный target или замороженный benchmark.

## 9. Authentication / reauthentication: второй вертикальный срез

Предлагаемое имя capability: `verify_auth_reauthentication`.

### 9.1. Подготовка

- Два синтетических customer-пользователя и доказанные server identities.
- В B06 worker private tmpfs хранить также текущие disposable passwords.
- Новые/старые пароли различны, имеют случайную достаточную энтропию и никогда
  не передаются через argv, host env, model input или Evidence.
- Подготовить фиксированную ожидаемую политику: смена пароля требует правильного
  текущего пароля. Источник требования записать в claim manifest.
- Сохранить source/config/image inventory с `changePassword`, login, whoami,
  user model и всеми реально используемыми helpers.

### 9.2. Одно основное испытание

Рабочее расписание с максимумом 17 HTTP exchanges:

| Группа | Запросы | Максимум |
| --- | --- | ---: |
| Baseline A | Обычный login с исходным паролем, независимый whoami | 2 |
| Positive control B | whoami B, корректная смена с текущим паролем, новый login B, whoami B | 4 |
| Anonymous control | Тот же класс операции без аутентификации, ожидается отказ | 1 |
| Negative control A | Неверный текущий пароль, затем baseline login и whoami A | 3 |
| Probe A | Смена собственного пароля без текущего пароля | 1 |
| Независимый readback | Login с новым, login со старым паролем, whoami однозначно успешной session | 3 |
| Проверка B и объекта | whoami B, owner-read отдельного объекта B, whoami B | 3 |
| Итого | Включая controls, login и readback | 17 |

Если ни один или оба credential-варианта успешны, результат неоднозначен.
При этом нельзя выбирать «подходящий» ответ; испытание inconclusive.
HTTP 200 от password-change или login сам по себе не доказывает эффект.

### 9.3. Повтор и агрегирование

1. Завершить trial 1 с сохранением одобренного действия и observations.
2. Уничтожить его disposable lab, проверить cleanup и неизменность исходника.
3. Создать новую generation с новыми accounts/credentials на том же source/image/config.
4. Заново построить runtime/fixture binding и получить approval trial 2.
5. Повторить полный протокол.
6. Проверить оба persisted records и сформировать итоговое Evidence.

Старые server IDs не обязаны совпадать: логические actor IDs сопоставляются
только через проверенную fixture mapping каждой generation. Нельзя принимать
старые токены или старое approval после reset.

### 9.4. Решение

- `confirmed`: оба trials имеют успешные controls; новый пароль после probe
  действительно дает login и серверную личность A, старый больше не дает входа;
  текущий пароль в probe не предоставлялся; fixture и source однозначно связаны.
- `rejected`: оба trials при рабочих controls отклоняют omission и сохраняют
  исходную credential-семантику: старый пароль работает, предполагаемый новый нет.
- `inconclusive`: непроверенная личность, оба/ни один login успешен, timeout
  изменяющей операции, потерянные records, один trial, failed control или cleanup error.

Это подтверждение пропуска reauthentication только для данного маршрута.
Нельзя автоматически присвоить выводам «полный захват чужого аккаунта» или CVSS.

### 9.5. Безопасный контроль

Нужна отдельная явно обозначенная operator safe-control snapshot настоящего
обработчика, где отсутствующий/пустой текущий пароль отклоняется. Полноценный login
и корректная смена с правильным текущим паролем должны продолжать работать.
Изменение не публикуется в оригинальном target и не добавляется задним числом
в frozen A04. Оно является отдельным acceptance control.

## 10. Code evaluation: отдельная ветка с feasibility gate

### 10.1. Gate до регистрации инструмента

1. Зафиксировать image, source snapshot, config и фактическую ветвь исполнения.
2. Подтвердить состояние `usernameXssChallenge` без включения отключенных функций.
3. Проверить, возможно ли вызвать настоящую boundary в offline disposable container.
4. Проверить, что эффект различим от простого отражения введенного текста.

Если хотя бы один пункт не выполнен, состояние `unsupported` с конкретной причиной.
Агент не получает candidate этого инструмента; finding остается inconclusive
с соответствующим reason code. В итоговых метриках отсутствие доступной проверки
не становится rejected или отрицательным тестом.

### 10.2. Если gate пройден

Предлагаемое имя: `verify_code_evaluation_marker`.

- Использовать только фиксированную операторскую грамматику инертного marker
  и арифметики над константами. Модель выбирает marker ID, но не исходный код.
- Никаких вызовов функций, импорта, циклов, команд, файлов, env или секретов.
- Контейнер без сети и host mounts; необходимые исходники и зависимости заранее
  находятся в закрепленном проверенном image. Target code на host не запускается.
- Нормальный literal control, отдельный observability control вычисления,
  отдельный невычисляющий negative control, два trials и одна резервная попытка.
- Простая отдельная арифметическая функция проверяет только observability.
  Ее выполнение нельзя выдавать за выполнение реального target handler.
- Source extraction или mock handler допускаются в unit-тестах, но не доказывают
  интеграцию с настоящей application boundary.

`confirmed` требует точного вычисленного результата, связанного с marker,
во всех нужных реальных trials и при успешных controls. `rejected` требует
доступной работоспособной boundary, корректных controls и двух безопасных исходов.
Отражение исходного текста без различимого вычисления дает inconclusive.

### 10.3. Правило закрытия этой части

Не обещать code-runtime coverage до gate. Для текущего benchmark допустимо
выпустить auth/redirect и честный `unsupported` по code evaluation.
Если приемка B06 требует все три runtime-семейства, до появления допустимого
положительного code-control статус всей задачи остается PARTIAL.
Название отчета и карточка должны явно отражать этот объем; synthetic-примеры
не закрывают недостающую интеграцию.

## 11. Бюджеты и учет затрат

Числа ниже являются предлагаемыми верхними границами новой B06-спецификации.
Перед реализацией утвердить расписание тестами accounting; не подменять ими
старые лимиты R01 без версии протокола.

| Семейство/фаза | Предлагаемый предел | Примечание |
| --- | ---: | --- |
| Redirect controls + два trials + counter | 8 HTTP | 7 основных запросов и 1 резерв для безопасного read-only повтора |
| Auth trial | 17 HTTP | Полный список из раздела 9 |
| Auth два trials | 35 HTTP | 34 основных и 1 резерв для безопасного read-only повтора |
| Code evaluation, если поддержан | 6 invocations | 5 основных и 1 резерв, только фиксированный marker |
| B04 prepare на generation | До 64 HTTP | Отдельный operator budget, фактически раньше 39 |
| Свежие B04 controls на generation | До 32 HTTP | Отдельный operator budget, фактически раньше 25 |
| Socket timeout | До 3 s | Также ограничен оставшимся wall time |
| Активная проверка одного trial | До 20 s | Deadline контролируется независимо от socket timeout |
| Request/response | 4 KiB / 64 KiB | Truncation исключает бинарный verdict |

Если auth использует две полные B04 preparation и две отдельные control-серии,
общий верхний предел равен `2*64 + 2*32 + 35 = 227 HTTP`, а не 35.
Readiness, image preparation, reset, startup и cleanup также измеряются и
показываются отдельно. Нельзя объявить setup бесплатным или скрыть полную
control-серию внутри одного условного «запроса».

Все health requests учитываются в отдельном ограниченном startup ledger.
Sink counter query тоже имеет явно указанную стоимость. После получения
фактического расписания пределы можно уменьшить с новой версией manifest.

Ресурсы target/worker первоначально наследуют проверенные ограничения B04.
Любые отличия, особенно для offline Node evaluation, записываются в manifest.

## 12. Retry, ошибки и очистка

- Изменяющий password-change нельзя автоматически повторять после timeout:
  операция могла выполниться. Такой trial заканчивается inconclusive и reset.
- Один разрешенный read-only retry записывается отдельным exchange и расходует
  резерв. Повтор не стирает запись о предыдущей ошибке.
- Истекший бюджет прерывает новые запросы и запускает cleanup в отдельном
  ограниченном lifecycle timeout.
- Ошибка cleanup отменяет положительный итог; состояние считается технически
  незавершенным. Следующая generation не создается поверх неизвестных ресурсов.
- Удаляются только контейнеры, volumes и network конкретного fixture generation.
  Ни Docker prune, ни очистка чужих ресурсов не используются.
- После reset старые handles, sessions и approvals отклоняются до запуска.
- Внешний raw command не становится обходным путем при отсутствии capability.

Существующие terminal statuses workflow сохраняются. `unsupported` является
причиной недостаточного Evidence, отображаемой как inconclusive с диагностикой.
`Validator DENY` остается `policy_blocked`, техническая ошибка не становится
безопасным security verdict.

## 13. Evidence и защита от ложного подтверждения

Interpreter проверяет:

1. Настоящее зарегистрированное имя capability и поддержанную версию schema.
2. Связь ActionProposal с approval digest и persisted ExecutionResult.
3. Source/route/map/profile/fixture/session bindings.
4. Наличие отдельных controls и отсутствие противоречивых expectations.
5. Фактическую server identity и нужный наблюдаемый эффект.
6. Полноту двух trials и reset provenance.
7. Согласованность exchange ledger и бюджета.
8. Отсутствие truncation, неизвестной ошибки и запрещенного follow.
9. Подтвержденную cleanup и неизменность исходного target.

Любое существенное несоответствие -> inconclusive. Свободный текст reasoning,
успешный HTTP status или worker verdict без фактов не дают confirmed.

Факты worker могут доказывать только заранее описанный эффект. Источник/image
связываются операторским provisioning; это не независимая бинарная аттестация.

Особенно важно для auth: password query и ответы приложения могут содержать
секреты. Полные URL, query strings, login/password-change bodies, Set-Cookie
и Authorization не экспортируются ни в telemetry, ни в audit, ни в UI.
Target logs с такими данными остаются приватными внутри disposable окружения
и не включаются в публикацию. Вне worker сохраняются только минимальные факты.

## 14. Интеграция в reasoning и отчет

Изменить `agent/verification.py`, чтобы он предлагал новый candidate только при:

- совпадении family/claim и уникальной B01-привязке;
- поддерживаемом runtime и разрешенном endpoint;
- готовой текущей fixture;
- достаточном оставшемся бюджете;
- отсутствии уже выполненного эквивалентного действия на том же trial.

Stub и LLM режимы выбирают один и тот же application-owned candidate.
Модель не формирует URL, пароль, role ID вне fixture, marker expression или reset.

Если подходящая проверка недоступна, сохранить понятную причину:
`no_operator_binding`, `fixture_not_ready`, `runtime_disabled`,
`insufficient_budget`, `control_failed`, `identity_changed`,
`trial_incomplete`, `cleanup_failed`.

FinalReport должен отвечать:

- какую конкретно гипотезу проверяли;
- какие controls прошли или не прошли;
- какой эффект увидели и как независимо его проверили;
- почему принят именно этот verdict;
- какой объем проверки не поддерживается;
- где лежат execution/audit/Evidence и что было очищено.

Для unsupported code: «Проверка выполнения кода недоступна в этом runtime:
соответствующая ветвь отключена конфигурацией. Исходник обнаружен, runtime-вывод
не получен». Для auth использовать точное название пропуска reauthentication.

Минимально использовать существующие UI-карточки и раскрываемые Evidence.
Отдельный redesign интерфейса и новый dashboard не требуются.

## 15. Порядок реализации и зависимости

| Шаг | Что сделать | Зависит от | Результат |
| --- | --- | --- | --- |
| B06.01 | Зафиксировать claims, DEV scope, support matrix и расхождения с R01 | B01, B04, A08 | B06-spec v1, критерии закрытия |
| B06.02 | Проверить code-evaluation feasibility по реальному pinned runtime | B06.01 | supported/unsupported с причинами, без probe при отключенной ветви |
| B06.03 | Спроектировать единый lifecycle/runtime-fixture bridge | B06.01 | Один target instance для controls и probe, typed bindings |
| B06.04 | Добавить typed observations/results и правила verdict | B06.01 | Строгие схемы и отрицательные schema tests |
| B06.05 | Добавить B06 operator profile и source/helper inventory | B06.03 | Новый профиль, B04 и historical profiles сохранены |
| B06.06 | Встроить новые bindings в Validator и Executor | B06.04, B06.05 | Mutation/replay/snapshot mismatch deny tests |
| B06.07 | Собрать redirect worker, controls и URI parsing | B06.04, B06.05 | Ограниченный полный protocol ledger |
| B06.08 | Подключить redirect candidate, Evidence и отчет | B06.06, B06.07 | Первый вертикальный сквозной срез |
| B06.09 | Пройти real redirect acceptance и безопасный patched control | B06.08 | Original confirmed, safe control rejected, weak Evidence inconclusive |
| B06.10 | Добавить приватное credential state и auth reset/trial lifecycle | B06.03, B06.05 | Credentials остаются внутри worker, две независимые generations |
| B06.11 | Реализовать auth controls/probe/login-readback | B06.04, B06.10 | 17-exchange trial, budgets, secret-free result |
| B06.12 | Подключить auth candidate, approved trials и aggregate Evidence | B06.06, B06.11 | Один trial не подтверждает всю гипотезу |
| B06.13 | Пройти real auth acceptance и safe-control snapshot | B06.12 | Повторяемый эффект/отказ, identity и cleanup проверены |
| B06.14 | Реализовать code capability только при supported gate | B06.02, B06.04, B06.06 | Настоящая boundary, controls, offline isolation |
| B06.15 | Общие fault-injection, regression и artifact audit | B06.09, B06.13, результат B06.14 | Проверенные статусы, бюджеты, отсутствие утечек |
| B06.16 | Отчет, пакет артефактов, review и публикация | B06.15 | Явный PASS/PARTIAL по заявленному объему |

Параллельно после B06.01 можно выполнять B06.02, проектирование B06.03 и модели
B06.04. После общей договоренности по bindings отдельно реализуются redirect
и auth. Интеграционные acceptance идут после рабочего вертикального среза.
Изменения общих schemas/Executor согласуются в одной ветке, чтобы не смешать
несовместимые варианты B05 и B06.

Рекомендуемый порядок фактической разработки:

```text
support/spec -> fixture bridge + schemas -> redirect целиком
-> auth целиком -> условная code-ветка -> общая приемка
```

## 16. Карта файлов

Новые пути ниже являются предложением для реализации, а не существующими модулями.

| Путь | Назначение |
| --- | --- |
| `docs/b06-verification-specification.md` | Claims, версия controls, budgets, support matrix |
| `targets/juice-b06-verification.yaml` | Новый операторский target/profile и route bindings |
| `schemas/b06_verification.py` | Typed fixture binding, observations, trial/family results |
| `executor/b06_runtime.py` | Операторский lifecycle bridge и trusted registry |
| `executor/b06_worker.py` | Фиксированные controls и probes внутри Docker |
| `executor/b06_verdicts.py` | Проверка фактов протокола; без LLM и сетевого доступа |
| `app/b06_acceptance.py` | Воспроизводимая Docker-приемка с новым output directory |
| `tests/test_b06_contracts.py` | Строгие схемы и insufficient-Evidence случаи |
| `tests/test_b06_redirect.py` | URI/status/controls/accounting, без сети вне lab |
| `tests/test_b06_auth.py` | Identity, credential effect, reset, два trials |
| `tests/test_b06_integration.py` | Opt-in real Docker E2E и cleanup |

Существующие registry/binding/policy/interpreter файлы расширяются минимально.
Не дублировать внутри нового worker основной Executor и permission policy.

## 17. Матрица тестирования

### 17.1. Контракты и bindings

- Неизвестный claim/tool/mode, лишний параметр или URL от модели.
- Нет fixture/generation/session binding; неподтвержденная или старая fixture.
- Endpoint не разрешен, map изменен, source изменен до/во время операции.
- Неоднозначный helper или registration, сдвиг строк, дубликат anchor.
- Мутация ActionProposal после approval и replay action ID.
- Controls и probe ошибочно используют один exchange ID.
- Результат содержит success flag без обязательных observations.
- Digest/audit/action/session refs относятся к разным trials.

### 17.2. Redirect

- Реальный redirect на закрепленный sink против отражения URL в body.
- Разрешенное назначение не считается finding.
- Negative control не проходит, хотя probe выглядит успешным.
- Повторный/malformed/отсутствующий Location, обрезанный ответ.
- Неоднозначное относительное значение, неожиданный scheme/host/port.
- Любая попытка follow или неожиданное посещение sink.
- Один успешный trial, второй timeout или иной destination.
- Safe-control snapshot дает rejected при работающем allowed control.

### 17.3. Reauthentication

- whoami 200 без user ID, не тот user, role swap или потерянная session.
- Password-change возвращает 200, но независимый login не подтверждает изменение.
- Новый и старый пароли одновременно работают или одновременно не работают.
- Positive correct-current control не работает.
- Wrong-current negative control случайно изменил пароль.
- Timeout изменяющей операции не вызывает повторный write.
- В одном trial условие подтверждено, второго trial/reset нет.
- Второй trial использует старые credentials/approval/source.
- Контрольный пользователь/объект изменился неожиданно.
- Safe-control snapshot требует текущий пароль и сохраняет нормальный login.

### 17.4. Code evaluation

- Отключенная runtime-ветвь дает unsupported, а не rejected.
- Literal reflection не превращается в вычисление.
- Observability control не работает; negative context вычисляет выражение.
- Синтетический marker изменен, не совпал результат или отсутствует второй trial.
- Отсутствует настоящая target boundary, хотя отдельная arithmetic fixture работает.
- Превышены output/CPU/time limits, контейнер не уничтожен.
- Запрещенная свободная строка кода не проходит валидацию.

### 17.5. Общие сбои

Timeout, broken JSON, truncation, HTTP 5xx, stale handle, failed cleanup,
поврежденные artifacts, недостаточный бюджет, отмена запуска, гонка reset/probe.
Для каждой ситуации заранее определить public reason и отсутствие бинарного verdict.

## 18. Приемочный запуск

Планируемый CLI после реализации:

```bash
python -m app.b06_acceptance \
  --repository artifacts/benchmark-target/juice-shop \
  --output artifacts/b06-acceptance-new
```

Требования к CLI:

- свежая папка вне target, без перезаписи старых попыток;
- чистый pinned checkout и уже подготовленные immutable images;
- preflight source/image/config/capability/fixture поддерживаемости;
- без API-ключа и без вызовов LLM для проверки механики capabilities;
- original и safe-control результаты отдельно;
- два независимых полных acceptance cycles для поддержанных семейств;
- управление только собственными ресурсами и cleanup в `finally`;
- при отсутствии prerequisites явный технический результат и сохраненная причина.

Сначала использовать фиксированную операторскую очередь Findings для проверки
самих capabilities. Это acceptance, не заявление о discovery Recall.
Затем выполнить ограниченный smoke через обычный pipeline на реальных кандидатах
из сохраненных B02/B03. Проверить IDs/provenance заново: нельзя подставлять
удобную другую находку, если старая не имеет подходящего source anchor.

Полный SAST+Scout+verification benchmark со сравнением метрик остается B09.
Количество закрытых challenges, SAST alerts и Evidence-confirmed случаев
не суммируется в одну метрику.

## 19. Пакет артефактов

Предлагаемая структура:

```text
artifacts/b06-acceptance-<attempt>/
  environment.json
  implementation.json
  support-matrix.json
  source-manifest.json
  profile-manifest.json
  auth/
    original/trial-1/
    original/trial-2/
    safe-control/
  redirect/
    original/
    safe-control/
  code/
    support-check.json
    original-or-explicit-unsupported/
  actions/
  approvals/
  executions/
  evidence/
  audit/
  lifecycle.jsonl
  cleanup.json
  summary.json
  report.md
  seal.json
```

В manifest включить implementation commit плюс SHA реально измеренных файлов,
source snapshot, target/worker image digests, profile/claim/budget versions,
reset adapter и resource limits. Не подписывать результаты только именем ветки.

Опубликовать redacted обмены, controls, effects и ссылки на records. Secret store,
raw login responses, cookies, password query, live keys и `.env` не включать.
Seal должен охватывать полный публичный пакет, а inventory совпадать с файлами.
Ручной review фиксирует спорные места и ограничения, не переписывая raw observations.

## 20. Критерии готовности и публикация

Для каждого объявленного поддержанным семейства:

- original target дает доказанный эффект на двух trials при рабочих controls;
- безопасный реальный control-вариант дает rejected;
- каждый insufficient-Evidence случай дает inconclusive;
- каждое активное действие имеет approval и registry dispatch;
- bindings относятся к правильным source/route/fixture/session;
- все HTTP/invocations/setup/readiness затраты объяснены;
- результаты воспроизводимы в независимой generation;
- cleanup завершена, original target и исторические locks неизменны;
- артефакты проверены, доступны команде и не содержат credentials.

Общие проверки перед merge:

```bash
python -m pytest -q -rs
ruff check app agent discovery evaluation executor schemas scoring security tools validator tests evidence
CFT_AGENT_MODE=stub python -m app.main
git diff --check
```

К ним добавляется opt-in Docker acceptance B06. Skipped integrations перечисляются
с причинами; успешные unit-тесты не заменяют незапущенную real acceptance.
Whitespace исходных machine logs не исправлять ради diff, если это меняет sealed
байты: проверять source/docs отдельно и явно записывать такой случай.

Работать в `codex/b06-runtime-verification` от актуального main. Перед merge
проверить изменения B05 в общих schemas/registry и согласовать совместимые
contracts. Коммитить только относящиеся к B06 изменения и публичные артефакты.
После review/merge выполнить push и сверить remote hash.

Финальный отчет содержит таблицу по семействам: supported/unsupported,
original/control verdict, число trials и exchanges, cleanup, Evidence refs.
Для полного PASS должны быть выполнены все критерии согласованного покрытия.
Если runtime code evaluation необходим по принятому объему, но gate не пройден,
итог B06 остается PARTIAL с конкретной незакрытой частью.

## 21. Что делать первым при переходе к коду

1. Создать рабочую ветку от актуального main.
2. Написать короткую B06-spec с claims, поддерживаемостью и версиями бюджетов.
3. Сразу проверить code-runtime gate и зафиксировать его результат.
4. Закрепить единую fixture/runtime связку, не смешивая два разных target.
5. Реализовать минимальный полный redirect-срез и пройти его Docker acceptance.
6. Реализовать stateful reauthentication-срез с независимым credential readback.
7. Только после этого расширять code-ветку, если gate разрешает настоящее покрытие.

Первый полезный промежуточный результат: один настоящий redirect Finding проходит
обычный workflow и получает проверенный verdict, а безопасный контроль проходит
тот же путь с противоположным результатом. После него уже можно проверять
правильность всей интеграции, не дожидаясь готовности остальных семейств.
