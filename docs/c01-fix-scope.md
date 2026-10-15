# C01: область исправлений и независимый оценщик

База реализации: `fb24e03` (последний main при начале работы, 15 октября 2026).
Цель: Juice Shop v20.2.0, commit `5658473cf8814459bf89000ce373b20ed0b4eb37`.
Владелец: Роман. C01 выбирает ровно **два семейства**, не обещает исправлять
все классы. Генерация LLM относится к C02, полный runtime verifier — к C03.

## Исходное подтверждение и выбор

Вход — неизменный `artifacts/handoffs/b09-single-2026-10-15.zip`.
SHA256: `6ba2f4d4fcc23871f96f1bb141eb62bfae5b792904252cdb2ff2c28980a2d5c7`.
Проверяются точный состав ZIP, SHA256 каждого файла, сохранённые execution,
audit и approved action trace существующим offline A05 replay. Таблица
`confirmed-review.json` только выбирает случаи; сама по себе подтверждением
не считается. Повторный Docker/LLM-прогон B09 для выбора не требуется.

| Семейство | Исходный случай / capability / endpoint | Допустимые файлы | Причина и направление патча |
|---|---|---|---|
| `sql-search` | JS-SQL-001 / verify_sql_injection / GET /rest/products/search | routes/search.ts | Интерполяция criteria в SQL; replacements/bind с сохранением фильтра deletedAt и сортировки |
| `redirect-allowlist` | JS-REDIRECT-001 / verify_redirect_destination / GET /redirect | lib/insecurity.ts **или** routes/redirect.ts | Подстрока разрешённого URL внутри чужого назначения; точная проверка назначения с сохранением восьми разрешённых адресов |

Один патч меняет ровно один существующий файл выбранного семейства. Разрешение
на два файла redirect не разрешает общий рефакторинг lib/insecurity.ts.
Формальная проверка scope не доказывает безопасность или отсутствие регрессий.
Для изменения других файлов нужна отдельная операторская версия registry.
SQL/login не включён автоматически в семейство исправляемого поиска.

`python -m app.fix_scope --output artifacts/c01-fresh-eligibility.json`
пересчитывает eligibility без модели, Docker и изменения исторических артефактов.
Результат: eligible=2, failed=0, ineligible=6 категорий исключения. Все остальные
семейства также исключены общим правилом `other`. Категории не являются числом
всех уязвимостей Juice Shop. Вне scope явно остаются login, listing, reauthentication,
access control, отключённый code evaluation и прочие классы. Причины в lock.json.
Если у выбранной семьи потеряны доказательства, она становится `failed`, а не
исчезает из знаменателя. Число попыток исправления здесь **0**, MTTR не измеряется.
Нарушение lock/целостности — техническая ошибка с ненулевым exit, не `eligible`.

## Независимые тесты и исходный эталон

`contracts/c01/families.json` задаёт функциональные требования и запрет shortcuts.
`evaluator.cjs` — фиксированный оценщик; `lock.json` связывает его, исходный
B09 ZIP с эталоном и реализацию harness. У патча нет разрешения менять тесты,
эталон, package.json, lockfiles, dependencies, настройки и сам оценщик.
`validate_candidate` перепроверяет lock и digest исходного файла, отвергает
traversal/ссылки, новые файлы, несколько файлов, metadata/mode changes и
неприменимый diff. Он не создаёт Executor approval и не применяет патч.
Текст C01 хешируется с каноническими LF, архив — по точным байтам. Исторический
корневой `.gitattributes` и входы A04 не меняются.

В оценщике SQL выражение извлекается из настоящего TypeScript AST, а не номера
строки или копии запроса. Выполняется Sequelize/SQLite из закреплённого образа,
с отдельными фиксированными Products, удалённым объектом и sentinel в другой
таблице. Проверяются поиск по имени/описанию, порядок, пустой/отсутствующий результат,
буквальный апостроф, исходная boolean-проба, другая boolean-проба и UNION к sentinel.
Отключение endpoint или возврат всегда пустого ответа не проходит функциональные тесты.

Для redirect из AST берутся фактические allowlist и helper. Все восемь исходных
адресов должны остаться разрешены; чужой URL запрещён. Независимые варианты:
query, fragment, userinfo, враждебный suffix и protocol-relative destination.
Внешние назначения не посещаются, DNS/network недоступны. deny-all и блокировка
только записанной пробы не принимаются.

Это квалификация **source-level** тестов на исходной причине, а не проверка
собранного приложения. Она не покрывает изменения логики вне извлечённого
выражения, интеграцию route/helper, нормализацию запроса/200-символьный лимит,
TypeScript build или runtime provenance. Эти обязательные проверки закреплены
для C03 ниже. VM не считается границей безопасности; граница — Docker.

## Реальная Docker-приёмка оценщика

```bash
python -m app.fix_scope_acceptance \
  --target artifacts/benchmark-target/juice-shop \
  --output artifacts/c01-fresh-qualification
```

Нужны Docker и уже установленный образ
`sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`.
Ничего скачивать для повторения текущей приёмки не требуется. Автоматического pull
нет. Четыре одноразовых networkless контейнера: non-root, read-only, caps drop,
1 CPU, 256 MiB, 32 PID, tmpfs 16 MiB, timeout 30 секунд на вариант.
Оценщик и данные монтируются отдельно readonly. Target code не исполняется на host.

| Вариант выражений | Ожидаемый результат |
|---|---|
| Original из AST закреплённого checkout | Исходные security tests выявляют обе причины |
| Operator reference: параметризация + точный allowlist | 13/13 passed |
| Deny-all | Функциональные проверки failed |
| Блокировка только записанных проб | Независимые security-проверки failed |

Публичные результаты: `docs/evidence/c01/qualification.json`. Все четыре
ожидаемых исхода получены, исходные файлы неизменны, cleanup подтверждён.
Reference — контроль пригодности тестов, **не LLM-патч и не FIXED**.
Два контрольных diff сохранены в `contracts/c01/reference/`: каждый проходит
`validate_candidate`, `git apply --check` и применение к одноразовой копии данных
до извлечения AST. Оригинальный checkout не получает diff.
Неуспех исходного кода ожидаем; он не считается неуспешной попыткой генерации.

## Контракт для C02/C03

До model generation нужно получить eligible и дать только выбранный прикладной
контекст и redacted Evidence; live credentials/пути оценщика в модель не передаются.
Перед apply: `validate_candidate`, immutable original snapshot, digest proposal
и source; применение только в disposable snapshot. После: повторная целостность
registry/evaluator/baseline. Существующий Stage 1 API автоматически не расширен.

C03 обязан исполнять build и штатные unit tests, затем start/smoke, повторять
**исходную каноническую capability** с B01 binding и дополнительные независимые
HTTP-варианты в отдельном доверенном процессе/контейнере, с readonly evaluator
вне writable target. Нельзя принимать stdout или exit code изменяемого target
за независимый verdict. Для SQL нужны успешные нормальные запросы, deletedAt,
порядок, apostrophe, no-match и лимит 200 символов; атакующие варианты не должны
менять результат за пределами буквального поиска. Для redirect нужны все
исходные Location, запрет каждого hostile варианта, работоспособность endpoint
до/после и отсутствие переходов к внешним назначениям. Проверка helper сама
по себе не подтверждает исправленный HTTP route.

Всё это проходит Validator → Executor → persisted Evidence, с matching action,
source snapshot, endpoint и audit; cleanup и оригинальная целостность обязательны.
`FIXED` требует BEFORE confirmed, AFTER явно rejected и всех обязательных
успешных тестов. Timeout, потеря сессии/маршрута, неожиданный HTTP status,
несовместимая AST-форма и отсутствие Evidence не превращаются в успех.
Failed/ineligible/attempted сохраняются раздельно; ineligible не входит в
success/attempted, но показывается рядом. Нельзя переносить подтверждение между
дублями, SQL/login и SQL/search или между source-level и runtime результатами.

## Замечания к обновлённому проекту

Исторический B09 подтверждает пять независимых случаев, но замер только один;
полнота подтверждения 5/27, CP/severity accuracy и MTTR не измерены. R09 даёт
3/27 runtime-confirmed и degraded/budget-limited diagnostic, не улучшение B09.
Это ограничения опубликованных результатов, они не исправляются выбором C01.
Существующий Stage 1 verifier поддерживает SQL/directory и старую привязку по
metadata file:line; он пока не является обобщённым C03 verifier двух выбранных
семейств с B01 и новым независимым оценщиком. Не заявляем обратного.

При локальной проверке обновлённого main устранены проблемы Windows: B02 получил
локальные LF attributes для hash-locked YAML; provenance fixture пишет явный LF;
symlink-тест B08 пропускается только при Windows error 1314. На платформах с
правами создания symlink проверка остаётся активной. Hash-lock и проверка
соответствия Git blob не ослаблены; исторические YAML и эталон не переписаны.
Опубликованные B02 JSON/stderr защищены от преобразования Git, а новые scorecards
пишутся с явными LF: повторный пересчёт сохраняет точные исходные байты.

## Проверки реализации

Полный pytest: **1329 passed, 35 skipped**, ошибок нет. Ruff,
`python -m app.main` и `git diff --check` прошли. Новые C01 tests входят
в полный прогон. Дополнительный поднабор B02/SAST/C01: 37 passed, 1 skipped.
Полный список пропусков сохранён в `docs/evidence/c01/pytest.txt`: Windows
symlink/POSIX ограничения, необязательный Semgrep CLI, отсутствующие opt-in
target/image/artifact paths и недоступный Docker daemon в момент общего прогона.
Они не считаются выполненными интеграциями. Отдельная реальная C01 Docker-приёмка
повторена после запуска Docker: original/reference/deny-all/probe-only имеют
ожидаемые исходы, source integrity и cleanup passed. Итоговые файлы защищены
SHA256 seal в `docs/evidence/c01/seal.json`.
