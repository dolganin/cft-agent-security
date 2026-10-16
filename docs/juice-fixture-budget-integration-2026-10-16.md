# NoSQL в общем запуске и учет HTTP-бюджета

Позднее 16 октября выполнен общий проход со всеми восемью fixture protocols
и B01, с явным бюджетом 1708 вместо стандартных 1024. Расход 1221, результат
11/27 подтверждений. [Отчет нового измерения](juice-all-ready-verification-report-2026-10-16.md).
Ниже сохранены условия предыдущей шестипротокольной серии.

Дата: 16 октября 2026. Ветка: `codex/juice-shop-plan-recovery`.

## Результат

NoSQL review-selector включен в стандартный `FIXTURE_GRANTS` диагностического
runner. Общая Docker-приемка выполнила все шесть зарегистрированных fixture-
протоколов за **74.068 секунды**, получила **6 confirmed** и потратила
**759 из 1024** единиц HTTP-бюджета. LLM-вызовов: 0. Исходник не изменен,
cleanup подтвержден для всех лабораторий. Каждый протокол использует свои
изолированные поколения.

| Операторский маршрут | Предварительный резерв | Списанный расход |
|---|---:|---:|
| `juice-basket-own-read` | 238 | 141 |
| `juice-basket-insert-owner-check` | 238 | 168 |
| `b06-reauthentication` | 194 | 118 |
| `juice-review-nosql-selector` | 250 | 160 |
| `juice-review-own-write` | 250 | 160 |
| `b06-redirect` | 38 | 12 |
| Сумма последовательных проверок | 1208 | 759 |

Все проверки предварительно резервируют полный допустимый расход из оставшегося
бюджета. После полного учета успешной проверки неиспользованная часть возвращается
для следующей. Поэтому сумма исторических предварительных резервов может превышать
1024; одновременно списанная/зарезервированная емкость остается в пределах лимита.
Сам лимит кампании и предел 256 для отдельной research scope сохранены.

## Исправленная причина

Раньше планировщик навсегда списывал весь резерв каждой завершенной проверки.
Шесть протоколов суммарно резервируют 1208, хотя наблюдаемый расход заметно ниже.
Из-за этого NoSQL нельзя было надежно добавить к существующей конфигурации.

`pipeline.verification_budget.verification_http_charge` возвращает неиспользованную
часть только для известных fixed B05/B06 verifiers, завершенного исполнения,
terminal Evidence, подтвержденной очистки и полного журнала запросов.
При отсутствующем признаке полноты, inconclusive, неизвестном исполнении,
неизвестном источнике или cleanup failure резерв остается списанным целиком.
Невалидные/отрицательные счетчики, bool вместо int и расход выше резерва вызывают
ошибку. Старые артефакты без признака полноты сохраняют прежнюю консервативную семантику.

До и после LLM research используется один и тот же учет. В summary сохраняются:

- `canonical_verification_http_requests_reserved`: суммарные исторические резервы;
- `canonical_verification_http_requests_observed`: измеренный расход по журналам;
- `canonical_verification_http_budget_charged`: реально списанная емкость;
- `http_request_budget_used`: списанная емкость вместе с research-запросами.

Исправлена и ветка исключения preverification: если fixture мог уже исполниться,
она удерживает полный возможный резерв данного протокола, а не прежние 4 запроса.

## Подготовка и readiness тоже учитываются

В B05 счетчик ранее пропускал отдельные readiness-пробы. Теперь
`b05_http_ledger` учитывает подготовку, контроли, только прирост provisioning,
проверочные обмены и все readiness attempts. Успешность соединения не гарантируется
для каждой readiness attempt; ее стоимость учитывается консервативно.
Возврат резерва требует полного журнала двух поколений без дублирования фаз.

Для B06 проверяются обе trial-записи и обе readiness-записи, setup и protocol
requests также входят в сумму. В принятой серии все шесть журналов полны.
Исторические 154 запроса отдельных review-приемок не включали readiness;
в новой серии полная стоимость каждого review-протокола составила 160.
Старые sealed результаты сохранены и не переписывались.

## Проверки

- Полный pytest: **1427 passed, 29 skipped**. Пропуски включают opt-in
  Docker/browser/provider integrations; общая шестипротокольная Docker-приемка
  отдельно выполнена явно и прошла.
- Ruff, `git diff --check` и smoke `python -m app.main` проходят.
- Негативные проверки бюджета покрывают незавершенное исполнение, cleanup failure,
  отсутствие/повреждение accounting, архивные результаты, недостающий readiness,
  повтор фазы, обратный ход provisioning counter и невозможность превысить резерв.
- Общая приемка: `test_all_registered_fixture_lifecycles_fit_one_campaign`,
  **1 passed**, шесть реально исполненных протоколов.
- SHA256 seal проверен для **88 файлов**. Канонический `replay_runtime` дважды
  пересчитал все шесть execution/audit; результаты совпали.
- Расход отдельно восстановлен из B05 lifecycle/trace и B06 trials/readiness;
  сумма 759 совпала с campaign summary.

## Артефакты и повторение

Принятый запуск:

```text
artifacts/juice-all-fixtures-budget-acceptance-2026-10-16/combined-fixtures/
```

Повторная Docker-приемка требует новой папки вывода:

```bash
CFT_RESEARCH_FIXTURE_ACCEPTANCE_CHECKOUT=/absolute/path/juice-shop \
CFT_RESEARCH_FIXTURE_ACCEPTANCE_OUTPUT=/absolute/path/fresh-output \
python -m pytest -q tests/test_research_fixture_campaign.py \
  -k all_registered_fixture_lifecycles
```

Offline-пересчет вердиктов после распаковки, без Docker/API:

```bash
CFT_REVIEW_ACCEPTANCE=/absolute/path/combined-fixtures python - <<'PY'
import json
import os
import tempfile
from pathlib import Path
from app.research_handoff import verify_seal
from app.research_score import replay_runtime
from pipeline.verification_budget import b05_http_ledger, verification_http_charge

root = Path(os.environ['CFT_REVIEW_ACCEPTANCE']).resolve(strict=True)
print('Verified files:', verify_seal(root))
with tempfile.TemporaryDirectory(prefix='cft-fixture-replay-') as temporary:
    view = Path(temporary)
    (view / 'campaign').symlink_to(root, target_is_directory=True)
    first, second = replay_runtime(view), replay_runtime(view)
    assert first == second and len(first) == 6
    assert all(row['status'] == 'confirmed' for row in first)
    print(first)

total = 0
for path in sorted((root / 'preverification/checks').glob('*/result.json')):
    row = json.loads(path.read_text())
    if row['origin'] == 'canonical_fixed_B05_verifier':
        trace = row['evidence']['observation']['facts']['b05_trace']
        log = path.parent / 'fixture-lifecycle/lifecycle.jsonl'
        records = [json.loads(line) for line in log.read_text().splitlines()]
        count, complete = b05_http_ledger(records, trace['exchange_count'])
        assert complete
    else:
        payload = json.loads(row['execution']['stdout'])
        log = path.parent / 'lifecycle.jsonl'
        records = [json.loads(line) for line in log.read_text().splitlines()]
        count = sum(t['http_exchanges'] + t['setup_http_exchanges'] for t in payload['trials'])
        count += sum(r['readiness_http_exchanges'] for r in records if r.get('phase') == 'ready')
    assert count == row['requests_observed'] == verification_http_charge(row)
    total += count
summary = json.loads((root / 'summary.json').read_text())
assert total == summary['http_request_budget_used'] <= 1024
print('Charged:', total)
PY
```

Приемка использует операторские исходные вопросы и фиксированные протоколы.
Она проверяет совместную работу, учет и доказательства; эти 6 confirmed не являются
новым измерением Recall/Precision по всем 27 случаям. Проверки отзывов на реальных
producer findings описаны в `juice-review-verification-report-2026-10-16.md`.
На момент исходной серии feedback ownership и чувствительные поля whoami еще
не были приняты; их отдельные результаты добавлены ниже.

## Две отдельные приемки после базовой серии

16 октября дополнительно приняты фиксированные проверки чувствительных полей
`whoami` и присвоения чужого `UserId` при создании feedback. Их отдельные
результаты и точные ограничения описаны в
[`juice-feedback-owner-report-2026-10-16.md`](juice-feedback-owner-report-2026-10-16.md).
Каждый протокол выполнил 20 проверочных запросов (10 на каждое из двух
независимых поколений), а полное фактическое lifecycle-списание составило 154
из 244 зарезервированных запросов. Оба standalone Evidence подтвердили
наблюдаемое свойство; seal и deterministic replay проверены.

Историческая общая шестипротокольная серия остается ровно шестью проверками и
759/1024. Две дополнительные проверки не запускались вместе с ней. Если обе
добавить поверх этой серии, ожидаемая сумма по сохраненным расходам была бы
1067, выше cap на 43. Лимит не повышали: общий планировщик учитывает каждую
проверку последовательно и оставляет неподтвержденный из-за нехватки резерва
кандидат в `review_pending`. Отдельные standalone acceptance не меняют метрики
полного A04 набора и не являются новым полным R09 run.
