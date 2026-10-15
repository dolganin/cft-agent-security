# Закрытие пробелов подтверждения Juice Shop

## Фактическая исходная точка

Неизмененный A04 matcher сопоставляет кандидатов с 27/27 положительных случаев.
Независимый replay execution/audit подтверждает 7/27. У остальных 20 статус
`not_run`: это не 20 провалившихся проверок. В архивном operator registry для
19 нет подходящего runtime-протокола; еще одному нужен source-property review.
Доступность отключенной code-evaluation ветки требует отдельной диагностики.

Новый `evaluation.juice_verification_gaps` заново пересчитывает исходный sealed
run и выпускает машинно-читаемую таблицу всех 27 случаев, кандидатов, anchors,
причин отсутствия исполнения и blockers. Это evaluator-only данные: их нельзя
подавать модели, использовать как разрешения или превращать в Evidence.

Результаты: `artifacts/juice-verification-gap-audit-2026-10-15/gaps.json` и `gaps.md`.
Исходные seals, отчеты, A04 и matcher не изменены.

## Семантический разбор 20 случаев

Сопоставление строк/семейств не доказывает совпадения проверяемого свойства.
Поэтому ниже отдельно разобраны фактические кандидаты. Приоритет означает
порядок инженерной работы, а не тяжесть уязвимости.

| Случай | Что есть и чего не хватает | Следующая проверка | Очередность |
|---|---|---|---|
| BOLA-003 | Selector обновления отзыва не содержит owner predicate | Отзывы двух тестовых ролей; owner/cross-owner update, независимый readback, отказ на отдельном control | 1 |
| NOSQL-001 | Тот же handler принимает request-controlled selector; это другое свойство | В той же fixture отдельно проверить scalar/operator-shaped selector; не переносить owner verdict автоматически | 1 |
| BOLA-004 | Writable UserId модели Feedback доступен generated API | Сессия A, одноразовый feedback, owner readback; чужой UserId и разрешенный counterpart | 2 |
| DATA-001 | Динамический выбор полей whoami без allowlist | Своя учетная запись, default/allowlisted/private fields; публиковать только имена и presence/hashes | 2 |
| AUTHZ-001 | В generated Product API отсутствует активный PUT auth guard | Отдельный продукт, anonymous/authenticated update и серверный readback; уничтожить поколение | 3 |
| AUTHZ-002 | Setter принимает клиентскую роль | Одноразовая регистрация и серверный readback роли; обычный customer control; без выдачи прав модели | 3 |
| BIZ-001 | Есть stock upper bound, но это не доказывает прием отрицательных quantities | Собственная корзина; нижняя/верхняя граница, persisted quantity и независимый расчет суммы | 4 |
| BIZ-002 | Coupon decoder влияет на скидку, но эффект еще не наблюдался | Выданный тестовый купон, целостность и поврежденный counterpart, readback суммы | 4 |
| DATA-002 | Handler возвращает metrics без локальной проверки auth | Анонимный и разрешенный control; заранее определить чувствительные поля; HTTP 200 недостаточно | 5 |
| CAPTCHA-001 | Ответ раскрывается; lookup не потребляет challenge | Правильный/неправильный ответ, повтор и свежий challenge; отдельный disposable feedback | 5 |
| FILE-002 | Проверка расширения предшествует нормализации имени | Только тестовый файл/маркер; allowed/normalized filename controls, без скачивания секретов | 6 |
| PATH-001 | Archive extraction пишет путь, containment требует проверки | Тестовый архив в изолированном writable tmpfs; маркер внутри/за application extraction root, никогда на host | 6 |
| SSRF-001 | Пользовательский URL достигает fetch | Только зарегистрированный локальный sink, нулевой внешний egress, контроль доставки marker | 6 |
| XXE-001 | Включены external entity/substitution flags; scanner observations дублируются | Только локальная entity fixture и owned marker; отсутствие host/Internet доступа; один case | 6 |
| NOSQL-002 | Track-order interpolation достигает $where | Контролируемый локальный набор заказов и независимый readback; никаких зависаний/DoS | 7 |
| RATE-001 | Key generator доверяет forwarding header | Малый фиксированный бюджет запросов и точный threshold; сравнить одинаковую/измененную identity key | 7 |
| XSS-001 | Query достигает trusted HTML API | Безвредный browser marker, text/escaped counterpart, без cookie/storage доступа | 8 |
| XSS-002 | Description продукта достигает trusted HTML API | Собственный product fixture, browser marker и безопасный counterpart, reset | 8 |
| CODE-001 | Source eval есть, Docker auto-safety отключает ветку | Не менять исходную цель ради подтверждения; отдельный availability gate, unsupported не rejected | Отдельно |
| CRYPTO-001 | Было доказано только наличие MD5, а не его связь с паролем | Cross-file AST: password setter → импортированный helper → слабый digest → сохраненное поле | Сделано как source-only |

Первые BOLA/NOSQL проверки можно объединить общей fixture, но у них должны
оставаться разные claims, controls и verdicts. Это не разрешение расширить
существующий B05 grant на новые маршруты: нужны отдельный operator registry,
binding, Validator, фиксированный worker и Evidence interpreter.

## Первый дополнительный proof: хранение пароля

`evidence.password_storage_review` теперь проверяет связь двух исходников:
`models/user.ts` и `lib/insecurity.ts`. Он требует точный namespace import,
единственный password setter в `User.init`, прямую передачу параметра helper,
экспортированный immutable helper и независимо разрешенный crypto import.
Проверяет единственный unsalted digest/update/storage chain и source hashes
до/после. Переопределение, другой импорт, строковый литерал вместо параметра,
salt/дополнительный update, неизвестный KDF или неоднозначность дают pending.

На закрепленном исходнике получен **source-condition confirmed**. В реальный
campaign это подключено отдельно к source reviews, без изменения runtime verdict.
Старые 7/27 не стали 8/27: результат не выдается за эксплуатацию или runtime proof.
Пароли/хеши пользователей не создаются и не публикуются, target code не исполняется.

Артефакт: `artifacts/juice-password-storage-source-2026-10-15`.

Исправлен еще один реальный routing defect: canonical family `code-evaluation`
не распознавалась существующим B06 guard, который проверял только legacy
`code-injection`. Обе формы теперь попадают в уже существующую диагностику
неподдерживаемого pinned runtime, только для двух зарегистрированных profile
source files и единственного B06 profile. Это не включает eval и не создает
исполняемую capability. Старый sealed run не переписан.

## Приемка следующих runtime-протоколов

1. Реальный vulnerable fixture и безопасный counterpart.
2. Неисправный control, неверная identity, stale binding: только inconclusive.
3. Неизменность исходной цели, одноразовые данные и проверенный cleanup.
4. Execution/audit readback и переносимый offline replay.
5. Только после короткой приемки включить протокол в общий запуск.

Новый полный LLM-прогон пока не нужен: он не создаст отсутствующие протоколы.
Текущие подтвержденные метрики остаются прежними до следующего реального
runtime acceptance. Никаких автоматических confirmed из сопоставления с эталоном.

## Воспроизведение

```bash
python -m evaluation.juice_verification_gaps \
  --run artifacts/juice-fixed-source-acceptance-retry-3-2026-10-15 \
  --output artifacts/juice-gaps-replayed
python -m app.juice_password_source_review \
  --checkout artifacts/benchmark-target/juice-shop \
  --output artifacts/juice-password-source-replayed
```

Обе output-папки должны быть новыми. Первая команда не требует Docker/LLM,
вторая требует только чистый закрепленный source checkout. Ни одна не запускает
pentest и не меняет сохраненные результаты.

## Проверка реализации

- Полный pytest: **1391 passed, 27 skipped**, 55.22 секунды.
- Ruff и `git diff --check` прошли; workflow smoke `app.main` завершился штатно.
- Source-chain tests проверяют прямую связь, другой импорт, shadow/reassignment,
  строку вместо параметра, salt/дополнительный update, неподдерживаемый helper,
  stale snapshot, symlink и настоящий pinned исходник.
- Gap audit повторно выполнен на реальных 105 sealed inputs; вывод совпал,
  все исходные байты сохранились. Tampering отклоняется до scoring.
- 27 пропусков — отдельные operator-provisioned Docker/SberLab/Autodealer,
  исторические demo artifacts и opt-in integration tests; они не объявлены PASS.
- Новых runtime-проверок на этом заходе не выполнялось. Старые runtime 7/27,
  severity/CP/FPR/MTTR и воспроизводимость не пересчитывались в улучшенные цифры.
