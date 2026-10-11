# R01: исправить замечания приемки

Работай в существующей ветке `codex/s01-integration-contracts`. Полностью
прочитай AGENTS.md, затем только нужные разделы R01. Основной агент параллельно
работает с K01: не меняй его файлы и не откатывай чужие изменения.

Область записи только `docs/r01-verification-specifications.md`,
`contracts/examples/r01/*`, `tests/test_r01_specifications.py`,
`docs/r01-acceptance-result.md`. Никаких production capabilities, interpreter,
schemas/policies, commit/push/merge, субагентов или живых attack payloads.

Исправь и проверь:

1. Auth-контроль сейчас совпадает с проверяемой операцией, и одновременно
   требует denial и unauthorized success. Выдели отдельный операторский
   заведомо защищенный control operation/fixture, не проверяемый кандидат.
   Positive control должен показывать доступность настоящей операции для B.
   Если отдельного отрицательного контроля нет, inconclusive. Те же
   требования проверь для redirect: probe и negative control не должны быть
   одним запросом с одновременно противоположными ожиданиями.
2. Запиши конкретные расписания HTTP-бюджетов для пяти семейств. В write-сценарии
   два цикла и контролы не помещаются в общие 8 запросов. Не ослабляй общий бюджет
   молча: назначь явный ограниченный семейный budget с перечнем операций,
   контролов, readback, повторов и cleanup. Контроль/проверка/reset должны
   укладываться в объявленное число. Reset операторский, не unreviewed model write.
3. Code-evaluation positive control должен доказывать наблюдаемость вычисления
   в разрешенном безопасном контексте; только literal reflection недостаточен.
   Оставь строго inert фиксированную арифметику, никаких shell/сети/секретов.
4. Дай synthetic confirmed/rejected/inconclusive примеры для КАЖДОГО из пяти
   семейств. Сохрани старые ownership-read examples совместимыми. Не выдумывай
   live Evidence. Все refs synthetic; production tooling не зарегистрировано.
5. Подтвержденные/отклоненные примеры требуют explicit controls, identity/owner
   proof где применимо, action/endpoint/source binding, repeat и cleanup.
   Tests должны проверять смысл этих обязательных фактов, а не только слова в
   Markdown или успешный Pydantic parse. Добавь mutation tests: missing negative
   control, no repeat, binding mismatch, ambiguous owner, mere HTTP200/reflection
   не соответствуют достаточным Evidence criteria.
6. Добавь machine-readable family specifications, если это полезно для tests,
   только как контрактные fixtures/spec templates под contracts/examples/r01,
   не второй production Evidence model. Docs и fixtures должны совпадать.

Выполни адресные pytest/Ruff, git diff --check. Верни короткий отчет
docs/r01-acceptance-result.md с измененными файлами, проверками и ограничениями.
Читай файлы маленькими целевыми окнами, не печатай гигантские журналы/каталоги:
прошлый запуск OpenCode переполнил context. Ничего не удаляй и не переписывай
из K01/K02 artifacts; ключи/.env/auth не читать. При denied tool операции
сообщи blocker, не обходи через другие средства.
