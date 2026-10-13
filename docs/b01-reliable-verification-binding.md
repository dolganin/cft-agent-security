# B01. Надёжная связь находки и проверки

Роман, 13 октября 2026. Основа: main `bc1bb6b`. Ветка:
`reliable-verification-binding`. Карточка:
[B01 в Miro](https://miro.com/app/board/uXjVEbkI518=/?moveToWidget=3458764686762034748).

## Реализация

Операторский профиль `targets/juice-verification.yaml` использует
`verification_routes`. Стабильные `route.id` и `handler_id` связывают семейство,
обработчик/caller/helper, HTTP method, service, endpoint и зарегистрированную
capability.
Для перехода на B01 оператор явно выбирает новый профиль через `--profile`.

`SourceSelector` содержит канонический относительный путь и token anchor.
Tree-sitter TypeScript/TSX разбирает реальный AST: комментарии, regex и template
strings не считаются границами функций. `extent=function` охватывает тело
объявленной функции/arrow function; `extent=anchor` — точный фрагмент регистрации.
Пробелы и переносы между токенами не являются идентификатором маршрута.
Parser и grammar закреплены в `pyproject.toml`: 0.25.2 / 0.23.2.

Это консервативная операторская карта, а не универсальный call-graph inference.
Caller/helper edges перечисляются явно. Общий helper с двумя маршрутами даёт
`inconclusive` и список candidate route IDs; первый элемент не выбирается.
Helper может находиться вне каталога сервиса только при явном операторском edge.
Неподдержанный синтаксис, отсутствующий или повторный anchor и отсутствие карты
также дают явный `inconclusive`. Автоматического расширения URL/target scope нет.

## Source snapshot и разрешение действия

`VerificationBinding` содержит canonical source file, finding ID, handler/route ID,
актуальный диапазон, SHA-256 прочитанного anchor, manifest хешей всех исходных
файлов карты, digest этого snapshot, digest операторской карты, endpoint/method
и точную capability/check/mode. Пределы: 64 routes, 16 source selectors на route,
256 файлов, 1 MiB на файл, 32 MiB на inventory. Пути вне checkout и ссылки запрещены.

Строка используется как положение наблюдения внутри snapshot, а не ключ разрешения.
Свежая находка после вставки строк выбирает тот же route ID. Архивная находка
может быть перенесена только по единственному точному ранее прочитанному anchor.
Если код самого anchor изменён, нужен новый scan; guessing и fuzzy rebinding нет.
Дубликат anchor не разрешается старым номером строки.

Порядок проверки:

1. RuntimeServiceMapBuilder фиксирует source inventory готовой managed session.
2. Приложение разрешает уникальную связь source → handler → route.
3. Reasoning layer выбирает только доступный candidate. Приложение прикрепляет
   binding; модель не определяет его digest или поля. Stub mode тоже использует
   настоящую capability вместо подтверждающего `safe_noop`.
4. Validator пересчитывает binding по операторскому профилю и текущим байтам.
   Approval digest охватывает весь ActionProposal, включая snapshot.
5. Executor повторно проверяет binding, session и runtime inventory перед запросом
   и проверяет исходники после исполнения. Изменение source/map/endpoint или
   mismatch snapshot не может дать успешное подтверждение.
6. Persisted execution и audit содержат action digest, endpoint, binding, run/session.
   Evidence interpreter проверяет эту запись и сохраняет provenance в Evidence.
   Несовпадение persisted binding даёт `inconclusive`, даже при HTTP success.

FinalReport сохраняет `binding_resolution`, включая причину неоднозначности.
Неизвестные маршруты не превращаются в `rejected`. Ошибки source availability
в публичном diagnostic не раскрывают локальные пути или байты исходников.

Runtime inventory — операторская привязка исходников к managed session. Он не
является независимой аттестацией того, что произвольный Docker image построен
именно из этих байтов. Нужны доверенные pinned image/Compose/build inputs.
Подготовка ролей, новые security capabilities и fix verification нового профиля
не заявляются: B04–B07/C выполняются отдельно. Исторический Stage1 профиль работает
по своему прежнему контракту; отсутствие B01 binding не подменяется другой картой.

## Приёмка

`python -m app.binding_acceptance --output artifacts/b01/new-attempt` выполняет
только фиксированные зарегистрированные проверки на pinned Juice Shop v20.2.0.
Нужен clean LF checkout `artifacts/benchmark-target/juice-shop` на commit
`5658473cf8814459bf89000ce373b20ed0b4eb37`, Docker и установленные project dependencies.
Target и Python worker images закреплены repository digests в этом CLI.
При отсутствии образов CLI не скачивает их автоматически. Модель/API-ключ не нужен.
Никакие target scripts не запускаются на host.

CLI создаёт internal network без published ports, одноразовый target и ограниченные
Docker workers. В отдельной копии трёх файлов выполняет search SQL, login SQL и
`/ftp`, вставляет три строки и повторяет те же действия. Исходный checkout неизменен.
Каждый action/approval/execution/Evidence, оба source snapshots и audit сохраняются.
Выходной directory должен быть новым; предыдущие попытки не перезаписываются.

Финальный фактический результат и SHA-256 полного архива:
[acceptance-summary.json](evidence/b01/acceptance-summary.json).
В архиве находятся final attempt, snapshots, seals, test logs и проверки.
Шесть реальных подтверждений доказывают работоспособность этих трёх существующих
capabilities после сдвига строк, а не расширение recall или завершение B09.

Дополнительные regression tests покрывают caller, helper вне service root,
неоднозначный общий helper, multiline registration/function header, regex/template
braces, stale/duplicate/missing anchor, malformed source, canonical path aliases,
подмену endpoint/service/tool, отзыв endpoint, изменение до/во время исполнения,
runtime snapshot mismatch, повреждённый persisted binding и approval mutation.

Исправлен Windows Docker-root translation в SAST normalizer. Проверка public/private
provenance сравнивает декодированный JSON вместо поиска неэкранированного Windows path.
Исторические locks и `security/source_paths.py` сохранены.

AST API: [официальный py-tree-sitter](https://github.com/tree-sitter/py-tree-sitter).
