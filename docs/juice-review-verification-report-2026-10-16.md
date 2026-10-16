# Проверка владения отзывами и NoSQL-селектора

Дополнение: подключение NoSQL к стандартному запуску и приемка всех шести
протоколов теперь завершены. Актуальный учет и результаты:
[`juice-fixture-budget-integration-2026-10-16.md`](juice-fixture-budget-integration-2026-10-16.md).
Раздел общего бюджета ниже описывает состояние до этого дополнения.

Дата: 16 октября 2026. Ветка: `codex/juice-shop-plan-recovery`.

## Результат

Два ранее отсутствовавших runtime-протокола прошли отдельные сквозные приемки
на закрепленном Juice Shop v20.2.0. Каждый получил настоящий source finding из
production detector, прошел B01 binding, Validator, SafeExecutor и независимый
Evidence interpreter. Каждый повторен в двух уничтожаемых Docker-поколениях.

| Свойство | Операторский check ID | Finding из producer | Результат |
|---|---|---|---|
| Изменение чужого отзыва по scalar ID | `juice-review-own-write-v1` | `juice-source-104e679fd5df61466a05` | confirmed |
| Интерпретация объекта ID как NoSQL-селектора | `juice-review-nosql-selector-v1` | `juice-source-1c9e9299890728691a56` | confirmed |

Архивный неизмененный A04 scorecard сопоставляет эти observation IDs с
`JS-BOLA-003` и `JS-NOSQL-001` соответственно. Исторические отчеты и labels
не переписывались. Найденные кандидаты ранее уже входили в detection coverage;
теперь добавлены доказательства двух разных проверяемых свойств.

## Что именно доказано

Scalar-протокол создает отзывы двух разных тестовых пользователей. Владелец
может изменить свой отзыв; анонимный запрос отклоняется. Затем пользователь A
меняет только созданный тестом отзыв B. Независимый readback доказывает изменение
сообщения, сохранение автора и других полей и неизменность остальных записей.

NoSQL-протокол создает два отзыва **одного владельца**. Сначала обычный scalar ID
меняет только одну запись. Анонимный запрос отклоняется. Затем фиксированный
worker отправляет операторный selector с точным списком двух созданных ID.
Сервер сообщает изменение двух записей, а последующее чтение подтверждает оба
изменения. Состав списка, владельцы, остальные поля и все прочие отзывы проверены.
Это отдельная проверка обработки селектора; cross-owner эффект для нее не нужен.

На каждый протокол: 26 проверочных HTTP-обменов в двух поколениях,
154 обмена с учетом подготовки/контролей, резерв 250. Cleanup и целостность
исходника проверены. Credentials и сообщения остаются в приватном Docker tmpfs;
доказательства содержат hashes и статусы.

Полномочия представлены отдельными check IDs и routes. Общая зарегистрированная
capability `verify_access_control` принимает только check ID. Произвольные ID,
операторы, URLs, credentials и тела запросов в ActionProposal запрещены.

## Проверки и артефакты

Финальные данные находятся в:

```text
artifacts/juice-review-protocols-final-2026-10-16-retry-1/
  b05-review-owner-v1/
  b05-review-nosql-v1/
```

В каждой папке: finding/provenance, operator manifest, action/approval,
execution, audit, lifecycle двух поколений, controls, отчет и SHA256 seal
из 26 файлов. Канонический `app.research_score.replay_runtime` дважды
пересчитал каждую приемку; результаты совпали и остались `confirmed`.

Проверки кода: **1408 passed, 29 skipped**, Ruff проходит,
`python -m app.main` проходит. Две явные Docker-интеграции отдельно:
**2 passed**. Пропуски общего набора включают opt-in интеграции, для которых
нужно явно предоставить Docker/browser/provider окружение. Эти два целевых
Docker-сценария выполнены явно. Контроли отказа, нарушения владельца/полей,
изменения посторонних записей, несовпадения binding, повторов и markers покрыты
unit-тестами. Runtime-проверка специально исправленного counterpart еще впереди.

Первая попытка 16 октября остановилась до исполнения из-за выключенного Docker;
ее папка без суффикса `retry-1` сохранена отдельно и не входит в принятый пакет.
Первый прототип NoSQL от 15 октября также не является финальной приемкой.

Новый NSU credential прошел один generation preflight через штатный adapter:
`nsu:qwen3.8-flash-next`, ready, 1.46 с. Ключ не сохранялся в коде/артефактах.
В двух Docker-приемках LLM не вызывалась.

## Offline replay после распаковки

Из корня текущей реализации, без Docker/LLM, передать абсолютную папку одной
приемки через переменную `CFT_REVIEW_ACCEPTANCE`:

```bash
CFT_REVIEW_ACCEPTANCE=/absolute/path/b05-review-nosql-v1 python - <<'PY'
import os
import tempfile
from pathlib import Path
from app.research_handoff import verify_seal
from app.research_score import replay_runtime

root = Path(os.environ['CFT_REVIEW_ACCEPTANCE']).resolve(strict=True)
print('Verified files:', verify_seal(root))
with tempfile.TemporaryDirectory(prefix='cft-review-replay-') as temporary:
    view = Path(temporary)
    (view / 'campaign').symlink_to(root, target_is_directory=True)
    first = replay_runtime(view)
    second = replay_runtime(view)
    assert first == second
    print(first)
PY
```

Временная ссылка позволяет использовать штатный replay, ожидающий подпапку
`campaign`; сохраненные артефакты не изменяются. На Windows для symlink могут
понадобиться developer mode или WSL. Для второй приемки изменить только путь.

## Статус общего плана

Это две короткие приемки возможностей с реальными producer findings.
Исследовательская LLM-часть здесь не измерялась. Исторический интегральный
результат **7/27** остается отдельным сохраненным измерением; нового полного
benchmark-run и новой общей таблицы метрик в этом пакете нет.

Scalar-протокол включен в `FIXTURE_GRANTS` диагностического runner.
NoSQL доступен через явный `app.research_campaign --fixture-grant b05.review-nosql.v1`.
Перед общим прогоном нужно включить его в общий scheduler с учетом бюджета:
существующие пять fixture-протоколов резервируют 958 запросов, шестой добавляет
250; сумма превышает текущие 1024. Сам лимит сохранен. Нужна проверенная
оптимизация учета/подготовки либо отдельный явно описанный verification pass.

Следующие свойства очереди: feedback ownership и выбор чувствительных полей
`whoami`, затем role assignment и anonymous product update. J05/J06 остаются
частичными, J09/J10 не закрыты этими двумя приемками.
