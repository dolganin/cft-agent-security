# B05 OWN-WRITE v2: разбор отрицательного контроля

Дата анализа: 2026-10-14. Анализ выполнен по актуальным документам и сохранённым sealed artifacts ветки `feature/b05-access-verification`, без новых Docker-вызовов и без изменения acceptance-пакетов.

## Вывод

OWN-WRITE v2 в `artifacts/b05-own-write-v2-20261014-v7/` остаётся **INCONCLUSIVE**. Отрицательный контроль не прошёл не из-за сетевого сбоя: запрос role A к другому BasketItem в basket role B получил HTTP 200, а независимое чтение role B зафиксировало изменение `quantity` и `updatedAt`. Операторская матрица при этом объявляет для A обновление B-owned объекта запрещённым.

Наблюдение совместимо с реальным отсутствием object-level authorization на `PUT /api/BasketItems/:id`, но одно лишь это измерение не превращается в R01 verdict: требуемый отрицательный контроль не прошёл. Ошибка данных или неверный role mapping не подтверждаются сохранёнными результатами: B04 profile верифицирует role A/B и владельца basket B; worker-код создаёт отдельные item refs и проверяет их вложенность и BasketId при чтении basket. Однако sealed trace не сохраняет сами числовые BasketItem ID и raw timestamps, поэтому независимая перепроверка точного ID-to-basket join и времени по одному portable пакету невозможна. Это ограничение аудируемости не объясняет HTTP 200 и эффект на readback, но должно оставаться явным.

Минимально допустимое действие сейчас — сохранить результат как INCONCLUSIVE. Исправление только harness-кода, исключение отрицательного контроля или замена его запросом с иным смыслом нарушили бы R01. Чтобы получить иной валидный результат, необходимы либо серверная owner-authorization на этой операции (тогда probe может быть корректно отклонён), либо формально рассмотренное и утверждённое изменение R01/кандидата с другим действительно эквивалентным authorization control. Последнее нельзя делать только в рамках этого анализа.

## Требование R01 и смысл контроля

Канонический раздел `docs/r01-verification-specifications.md`, R01-OWN-WRITE, требует:

- отдельный target B-owned объект для отрицательного контроля;
- доказательство, что у A нет права обновлять этот объект;
- PUT от A, после которого значение объекта должно остаться прежним;
- независимое readback владельцем B;
- успешные positive controls владельца B и self-write A;
- два повторённых probe на объекте-кандидате, reset между пробами и проверку отсутствия посторонних изменений.

Смысл отрицательного контроля — доказать, что проверяемая политика действительно отказывает в запрещённом межпользовательском обновлении, а не просто подтвердить доступность endpoint или работоспособность сессии. Для BasketItem ожидаемое серверное правило следует из relation: item находится в корзине B, A не имеет update permission на basket B, поэтому сервер должен проверить владельца родительской корзины для текущей authenticated identity и запретить A изменение item. Это предполагаемое правило безопасности; оно не является обнаруженной реализацией target.

В source review кандидата (`docs/b05-r01-own-write-v2-candidate.md`) зафиксировано, что `PUT /api/BasketItems/:id` выполняет authentication и проверку количества, затем передаёт обновление в общий handler. `BasketItem` не имеет `UserId`; связь с пользователем проходит через `BasketId`. В просмотренном route/model не найден BasketItem-specific owner check. Hooks защищают `BasketId` и `ProductId` от изменения, но сами по себе не запрещают изменение `quantity` чужого item.

## Что сравнивают сохранённые события

В sealed trace используются ссылки на объекты и role IDs; секреты не сохраняются. Числа в колонке «до/после» доступны лишь как SHA-256 значения поля, не как raw значения.

| Свойство | Основные probes | Отрицательный контроль |
|---|---|---|
| Запрос | `probe-b-t1`, `probe-b-t2`: role A, `PUT`, `basket-write-candidate-b`, endpoint ID `basket-write`, HTTP 200 | `nc-a-update`: role A, `PUT`, `basket-write-negative-b`, тот же endpoint ID, HTTP 200 |
| Независимый readback | `probe-b-t1-readback`, `probe-b-t2-readback`: role B, `GET`, endpoint ID `basket-read`, HTTP 200 | `nc-b-readback`: role B, `GET`, endpoint ID `basket-read`, HTTP 200 |
| Владелец / permission relation | B04 generation profile подтверждает owner basket B = role B; controls `ownership=true`, `permission_relation=true` | Тот же role B и basket B; отдельный item создан оператором для role B; lifecycle подтверждает role A update permission на basket B = false |
| Поле количества | baseline hash `6b86…` (значение 1); оба probe readback hash `d473…` (значение 2) | fixture item создаётся с quantity 1; readback отмечает `quantity` среди изменённых полей и hash `d473…` (значение 2) |
| `updatedAt` | `changed_fields=[quantity, updatedAt]`, `timestamp_update_proven=true` в обоих trial readback | Те же `changed_fields` и `timestamp_update_proven=true` на negative-control readback |
| `createdAt` и отношения | `created_at_unchanged=true`, `relationships_unchanged=true`; BasketId/ProductId/id заявлены неизменными | те же флаги true для readback контроля |
| Повторяемость / cleanup | два reset-separated candidate trial; final quantity hash возвращён к baseline; reset, cleanup, integrity true | один отдельный контроль в начальной generation; это не trial и не повторный результат |

`basket-write-candidate-b` и `basket-write-negative-b` — разные BasketItem. В worker mapping они создаются внутри одной basket B с разными ProductId (соответственно 2 и 4); оба исходно имеют quantity 1. Basket B имеет server object ID 7 и owner user ID 26 в сохранённых B04 profile snapshots. В source/registry mapping item ref разрешается в свой item ID и общий parent BasketId. Сам числовой BasketItem ID, конкретный BasketId на каждый exchange и raw cookie/session token в trace не сериализованы; `object_ref`, role, generation hashes и identity hashes являются сохранённым redacted provenance. Сессии A/B проверялись в lifecycle identity exchanges и хранились в private worker state, но по seal нельзя сравнить их секретные значения.

Endpoint IDs разрешаются операторским registry: `basket-write` = `PUT /api/BasketItems/:id`; `basket-read` — чтение корзины владельца через `/rest/basket/:id`. Trace фиксирует role B как независимого читателя. Численные значения `updatedAt` также не сохранены: Evidence подтверждает только изменение поля и что timestamp стал позже baseline.

### Точная причина провала

Отрицательный контроль ожидает одновременно отказ PUT (`400`, `401`, `403` или `404`) и отсутствие эффекта по B readback. В v7 PUT вернул **200**, а readback B обнаружил `quantity` и `updatedAt` как изменившиеся. Поэтому `negative_control=false`, а deterministic interpreter правильно оставил итог `INCONCLUSIVE`; sealed manifest имеет `status=incomplete`. Это не ложный отказ из-за HTTP 200 без эффекта и не техническая ошибка: trace сообщает `technical_error=null`, завершённые 12/12 exchanges, успешные reset/cleanup/integrity.

Флаг `other_items_unchanged=false` на negative readback не является причиной отказа контроля: отдельный B owner-write positive control до него правомерно изменил другой B BasketItem, а baseline массива всех элементов ещё не был обновлён. Сама отрицательная проверка сравнивает поле текущего negative-control item и уже показывает его изменение. Для двух candidate readback это не мешало exact-delta проверкам; там baseline массива снимался после controls.

## Классификация

- **Техническая ошибка / инфраструктура:** нет. Полный bounded run завершён; `technical_error=null`, все 12 обменов выполнены, reset, cleanup и source integrity прошли.
- **Ожидаемое R01 поведение:** контроль не выполнил требование «значение осталось неизменным». R01 трактует это как неуспешный обязательный control, поэтому результат обязан оставаться INCONCLUSIVE.
- **Вероятное поведение target:** разрешён cross-owner update на том же endpoint и в той же объектной модели. Это согласуется с source review отсутствия owner predicate, но не заменяет R01-вердикт.
- **Ошибка fixture / identity mapping:** подтверждений нет. Lifecycle доказывает server identities role A=25 и role B=26, owner basket B=26, отдельные item refs и permission A→basket B `update=false`; run отмечает ownership и permission relation true. Raw item IDs не включены в sealed trace, поэтому точный join нельзя независимо воспроизвести из portable Evidence.
- **Ошибка ожиданий R01 / конфликт тестовой конструкции:** обнаружен существенный конфликт. Основной probe и negative control — оба PUT от A к разным items в той же B-owned basket, по одному endpoint и с тем же owner/permission relation. Контракт требует, чтобы один такой запрос изменил объект-кандидат, а другой при эквивалентной авторизации был отвергнут. В текущем Juice Shop source не найдено правила, различающего эти items по правам. Следовательно, контроль закономерно срабатывает на той же общей недостающей защите, которую предполагает probe; это не основание ослабить критерий, а вопрос к пригодности пары fixture/контракта.
- **Недостаточность Evidence:** есть для независимого точного сравнения числовых BasketItem IDs, per-request BasketId, raw quantities/timestamps и session token continuity. Есть достаточный сохранённый индикатор эффекта: A update 200, B independent readback, changed field names, timestamp proof, sealed hashes и verified roles/ownership. Ограничение не следует маскировать raw data, которых нет.

## Отдельное OWNERSHIP-TRANSFER наблюдение

`artifacts/b05-ownership-transfer-v1-20261014-v1/` — отдельный DEV сценарий, не OWN-WRITE и не R01-AUTH. Его Evidence — **CONFIRMED**: два поколения имеют SQLite proof pairs для одного `address-b` (object ID 8), read-only query `addresses-owner-readonly-v1`: до PUT owner B/user 26, после PUT owner A/user 25. Обе пары соответствуют своим generation hashes; identity, permission, отдельный denied-read control, reset, cleanup и integrity отмечены успешными. PUT выполнен role A; readback A успешен, прежний owner B получает 400. Seal содержит 13 файлов, все SHA-256 совпали; manifest `passed`, 12 exchanges. Это подтверждает только narrow DEV ownership-transfer observation и не меняет OWN-WRITE verdict.

Для OWN-WRITE v7 seal содержит 14 файлов, все SHA-256 совпали. Manifest `incomplete`, Evidence `inconclusive`, 12 exchanges. Существующий итоговый B05 report согласован с этим состоянием и последней проверкой: targeted **204 passed, 3 skipped**; full suite **1000 passed, 27 skipped, 21 failed** из-за известных freeze digest mismatches A01/A04/A06 на `.gitattributes`; отдельно описано OWNERSHIP-TRANSFER runtime result и причина OWN-WRITE INCONCLUSIVE. Итоговый отчет не называет измерение успешным R01 результатом.

## Что допустимо делать дальше

1. Сохранить v7 как есть и не переводить OWN-WRITE из INCONCLUSIVE. Не удалять/не игнорировать отрицательный контроль и не пересчитывать его как успешный.
2. Для диагностируемости будущего acceptance рассмотреть (с отдельным review, без изменения старого пакета) дополнительные redacted runtime facts: opaque BasketItem IDs или их стабильные salted digests; связь item→BasketId→owner; baseline/after quantity digests для каждого object; timestamps или проверяемые timestamp digests; generation/session identity binding per exchange. Не сохранять session tokens.
3. Если цель — проверить ту же owner authorization, сначала выбрать один из двух честных путей: (a) тестировать target, где реально есть owner-scoped update policy и тогда ожидать deny и для probe, если обе записи эквивалентны; либо (b) предложить оператору формальное изменение R01/семейства контроля, которое задаёт независимую, семантически релевантную контрольную границу для уязвимого target. Контроль на stock/validation error, несуществующем ID или произвольном endpoint не эквивалентен и не подходит без отдельного обоснования и operator approval.
4. Любой новый runtime acceptance требует отдельной авторизации и нового sealed output. Текущие артефакты не переписывать.

До формального решения по контролю и валидного прохождения всех обязательных R01 controls статус остаётся **OWN-WRITE INCONCLUSIVE / B05 INCOMPLETE**. Успешная неавторизованная запись сразу в probe и control не является доказательством межзапусковой стабильности или R01-confirmed finding.

