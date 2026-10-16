# C02: настоящие LLM-предложения патчей

Владелец: Роман. База: main `bdbac9f`, C01 уже включён.
Цель: Juice Shop v20.2.0, commit `5658473cf8814459bf89000ce373b20ed0b4eb37`.

`app.patch_propose` вызывает **ProviderFailoverClient**, получает строго
типизированный `BoundedPatchResponse` (наследник канонического ProposedPatch),
проверяет его и сохраняет `PatchReviewArtifact`. IntegrationPatchClient,
контрольные C01 diff и генерация патча приложением в этом пути отсутствуют.
Приложение только канонизирует прошедший проверку diff и восстанавливает исходный
контекст; новую строку исправления пишет LLM. Оригинал не меняется, патч не
применяется, команды модели не исполняются.

## Вход и границы

Оператор выбирает ровно одну C01 family: `sql-search` или `redirect-allowlist`.
Из sealed B09 выбирается единственный соответствующий evidence-backed confirmed
report. C01 повторно проверяет execution/audit/approved trace. До обращения к
модели проверяется **весь** tracked snapshot: commit, 1300 файлов, точные Git
blob bytes и `files_sha256` должны совпасть с исходным B09. Dirty, другой snapshot,
изменённый evaluator lock и отсутствующее подтверждение не дают ready proposal.
Байты выбранного файла дополнительно сверяются с Git blob закреплённого
коммита перед отправкой: изменение/восстановление working file между чтениями
не позволяет отправить чужой контекст.

Модель получает только:

- finding ID, family, имя разрешённого файла, source digest и границы окна;
- numbered source window вокруг единственного выбранного TypeScript AST узла;
- операторское описание причины и требуемого поведения;
- выбранные очищенные Evidence facts: verdict, reliability, capability,
  action/evidence ID, summary, признаки повторённых контролей или число trials;
- формат diff и ограничения размера.

Полный report, raw HTTP bodies, credentials, private fixture state, local paths,
оригинальные артефакты, эталон, тесты оценщика и reference patches модели не
передаются. В частности, seeded private key из начала `lib/insecurity.ts`
не входит в окно redirect helper. Маскированное или секретное окно отклоняется
до запроса. Текст источника/Evidence — недоверенные данные, не инструкции.

Ограничения: source file 128 KiB; source window до 80 строк / 12 KiB;
проекция request до 24 KiB (плюс фиксированная schema/transport envelope);
diff до 16 KiB, строки до 2000 символов и максимум
64 добавленных/удалённых строк. Один операторский route, одна попытка без
schema/network retry; timeout HTTP 45 секунд, общий provider deadline 60 секунд,
output budget 3072 tokens. Transport использует существующий total deadline.

## Детерминированные проверки

Проверяются строгая схема без дополнительных полей, finding ID, точные headers,
paths, hunk counts/context, source digest и AST window. Затем C01 проверяет
ровно один существующий разрешённый файл и целостность защищённого оценщика.
Тесты, baseline, secrets, manifests, dependencies, новые файлы, mode changes,
linked/traversal paths и массовые несвязанные изменения не разрешены.

Текущая политика намеренно узкая:

- SQL: только исходная строка запроса; bind/replacements с согласованным
  placeholder, исходные SELECT, deletedAt, ORDER BY и `%criteria%` сохраняются.
- Redirect: только замена `url.includes(allowedUrl)` на строгую проверку
  равенства в прежнем boolean accumulator. Loop, allowlist, helper и handler
  не отключаются. Допустимы обе стороны сравнения `===`.

Deny-all, startsWith/substring, произвольные вызовы, удаление функции или
соседних защит отвергаются независимо от объяснения модели. Другие безопасные
рефакторинги тоже могут быть отклонены: расширение требует операторской политики,
а не разрешения модели. Эти проверки устанавливают допустимость предложения,
не устраняют необходимость build/function/security tests в C03.

Распознанные secrets и точные настроенные provider credentials не допускаются
в model request/response. Секретный ответ целиком отвергается до записи raw
response. Сохраняются digest и причина отказа; отвергнутые diff/rationale не
публикуются. Разрешённый rationale остаётся недоверенным текстом предложения.
Это не доказательство обнаружения всех возможных секретов; разрешённые формы
изменения кода дополнительно не дают вводить произвольные литералы/операции.

После ответа вновь проверяются source snapshot и C01 lock. Изменение входа
аннулирует review. Ready требует реального успешного provider attempt и
маршрута модели. Статусы `ready_for_review`, `rejected`, `failed`, `ineligible`
различаются; отказ и потеря provenance не превращаются в успех.

## Запуск

Ключ провайдера хранится только в локальном ignored `.env`:
`NSU_OPENWEBUI_KEY`. В diff, запрос модели или published bundle он не входит.
Для генерации Docker и новые downloads не нужны: target читается как данные,
модель вызывается через настроенный API.

```bash
python -m app.patch_propose \
  --target artifacts/benchmark-target/juice-shop \
  --family sql-search \
  --output artifacts/c02-new-sql

python -m app.patch_propose \
  --target artifacts/benchmark-target/juice-shop \
  --family redirect-allowlist \
  --output artifacts/c02-new-redirect
```

Default route: `nsu:qwen3.8-flash-next`, reasoning low. `--route` выбирается
оператором, не моделью. Внешний fallback автоматически не включается.
Output должен быть новым каталогом вне target; существующие результаты
не перезаписываются. Exit 0 означает допустимое предложение; exit 2 — failed,
rejected или ineligible, **не** результат security verification.

Файлы успешного запуска:

- `request.json`: фактически переданный bounded context и system prompt;
- `model-response.json`: исходный проверенный структурированный ответ LLM;
- `generation.json`: provenance, source/report/request/response digests,
  provider attempts, итоговый статус и проверка original integrity;
- `patch-review.json`: канонический ProposedPatch внутри существующего контракта
  PatchReviewArtifact, с `applied=false`, `security_verified=false`.

Response SHA256 вычисляется по `BoundedPatchResponse.model_dump_json()`.
Request SHA256 — по `json.dumps(request, ensure_ascii=False, sort_keys=True)`.
Proposal digest — по каноническому ProposedPatch.model_dump_json(). Они
проверяются раздельно: добавленный исходный context не выдаётся за текст модели.
Provider provenance — журнал доверенного адаптера, не криптографическая
аттестация провайдера. Unit transport doubles не считаются live generation.

## Реальная приёмка

Для обеих семей выполнены реальные запросы `nsu/qwen3.8-flash-next`:
финальные SQL и redirect получили `ready_for_review`, один успешный provider
attempt каждый. Сохранены исходные model responses и канонические review;
весь исходный snapshot неизменён. Патчи не применялись, target не запускался.

Всего в ходе разработки сделано десять отдельных вызовов: восемь допустимых
предложений и два rejected. Первая SQL-попытка отклонена общим gate
`diff_scope_or_defensive_policy`; сырой ответ по политике не сохранён, точная
подпричина не заявляется. Затем уточнён формат hunk в запросе. Промежуточные
запуски до сохранения raw response отделены от двух принятых финальных.
Первый финальный redirect также получил `invalid_diff_format_or_window`;
отдельный повторный операторский запуск принят, отказ сохранён. Это функциональная
приёмка C02, не метрика качества исправлений и не C04 retry loop.

Публичный пакет и SHA256 seal: `docs/evidence/c02/`. В нём сохранены также
неуспех и промежуточные попытки. Реальные credentials и `.env` исключены.
Полноценные BEFORE/AFTER, build/tests/start/smoke, исправление handler/runtime
и окончательный `FIXED` относятся к C03. Существующий Stage 1 API не изменён.

## Проверки реализации

Полный pytest: **1360 passed, 29 skipped**, ошибок нет. Новые тесты C02:
25 passed. Ruff, `python -m app.main`, `git diff --check` прошли.
В `docs/evidence/c02/pytest.txt` сохранён точный список пропусков: Windows
symlink/POSIX ограничения, opt-in интеграции без image/target/artifact paths,
необязательный Semgrep CLI. Они не считаются выполненными интеграциями.
Проверены неправильные paths/schema/ID/size, отключение защит, секреты в diff
и rationale, отсутствие ключа, изменение source во время ответа, output overwrite
и запрет IntegrationPatchClient, гонка контекста и тайм-аут snapshot check.
Тестовые transport doubles отделены от десяти
реальных API-вызовов в опубликованном пакете.
