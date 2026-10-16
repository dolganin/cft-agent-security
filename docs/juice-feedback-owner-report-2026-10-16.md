# Runtime-проверки чувствительных полей и атрибуции feedback

Дата: 16 октября 2026. Ветка: `codex/juice-shop-plan-recovery`.
Target: неизмененный Juice Shop v20.2.0, commit
`5658473cf8814459bf89000ce373b20ed0b4eb37`.

## Краткий итог

Две фиксированные проверки прошли через зарегистрированные B05 routes,
Validator, SafeExecutor и независимую property-specific Evidence-оценку.
Каждая выполнена на двух раздельных Docker-поколениях, повторный offline replay
совпал с сохраненным Evidence. На каждый protocol ушло 20 запросов проверки
(10 в каждом поколении); с подготовкой, controls и readiness — 154 запроса при
резерве 244. Внешних целей, LLM/API-вызовов и чтения benchmark labels не было.

| Проверяемое свойство | Результат | Что подтверждено |
|---|---|---|
| Выбор приватного поля `password` у `/rest/user/whoami` | `confirmed` в 2/2 поколениях | Сервер вернул поле с MD5-хешем пароля созданной тестовой учётной записи; хеш совпал с независимо вычисленным sentinel. Значение в отчет не записывалось. |
| Атрибуция отзыва через `POST /api/Feedbacks` | `confirmed` в 2/2 поколениях | Пользователь A создал синтетический отзыв с `UserId` пользователя B; B отдельно прочитал сохраненную строку, и ее `UserId` и контрольный маркер совпали. |

Первое подтверждение означает раскрытие хеша, а не исходного пароля. Второе
означает возможность подделать автора отзыва, а не запрет публичного создания
отзывов: Juice Shop намеренно разрешает отправлять feedback без входа. Мы также
не утверждаем, что этот endpoint дает доступ к чужим приватным отзывам.

## Как устроена проверка

Для `whoami` worker сравнивает обычный ответ, фиксированный допустимый выбор
полей, запрос `password`, анонимный запрос и неизвестное поле. В артефакты
попадают только статусы, признаки наличия и хеши. Для feedback worker сначала
создает и читает контрольную запись владельцем B, затем отправляет запись с
`UserId` B от лица A и проверяет её независимым readback B. В обоих случаях
до и после проверяется серверная личность пользователей; после первого
поколения лаборатория уничтожается и создается заново.

Это закрытые фиксированные протоколы. Модель не получает токены, ID записей,
произвольное тело запроса или новую execution capability. Feedback CAPTCHA
решается локальным AST-вычислителем только для целочисленных `+`, `-`, `*`.
Парсер специально допускает `captchaId=0`, потому что счётчик закрепленной
версии Juice Shop начинается с нуля; проверки положительности ID пользователей
и объектов не изменялись.

## Приемка и артефакты

Финальные sealed-пакеты:

```text
artifacts/juice-user-fields-acceptance-2026-10-16-retry-1/
artifacts/juice-feedback-owner-acceptance-2026-10-16-retry-3/
```

В каждом пакете 13 файлов: action, binding, validator result, persisted
execution, audit, typed trace, Evidence, lifecycle двух поколений, manifest и
SHA256 seal. Оба seal проверены; повторная оценка из сохраненных action+trace
дала тот же verdict, что и сохраненное Evidence. Cleanup подтвержден, исходник
target остался чистым и соответствует закрепленному commit.

Повторить только feedback-приемку в новой пустой папке:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m app.access_verification_acceptance \
  --repository artifacts/benchmark-target/juice-shop \
  --output artifacts/juice-feedback-owner-acceptance-<new-id> \
  --check-id juice-feedback-owner-v1
```

Проверить seal и детерминированный offline replay обоих пакетов:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python - <<'PY'
import json
from pathlib import Path

from app.research_handoff import verify_seal
from evidence.access_control import evaluate_access_check
from schemas.access_verification import AccessCheckTrace
from schemas.action import ActionProposal

for root in (
    Path("artifacts/juice-user-fields-acceptance-2026-10-16-retry-1"),
    Path("artifacts/juice-feedback-owner-acceptance-2026-10-16-retry-3"),
):
    print(root, "sealed files:", verify_seal(root))
    check = next(path for path in root.iterdir() if path.is_dir())
    action = ActionProposal.model_validate(json.loads((check / "action.json").read_text()))
    trace = AccessCheckTrace.model_validate(json.loads((check / "trace.json").read_text()))
    saved = json.loads((check / "evidence.json").read_text())["observation"]["facts"]["b05_evidence"]
    replayed = evaluate_access_check(trace, action).model_dump(mode="json")
    assert replayed == saved
    print("offline replay:", replayed["verdict"])
PY
```

Первые две feedback-попытки 16 октября завершили cleanup, но не дошли до
проверочного HTTP-запроса: общий helper отвергал корректный начальный
`captchaId=0`. Их sealed diagnostics сохранены отдельно в каталогах `retry-1`
и `retry-2`; они не являются результатами теста. Исправлен только парсер
CAPTCHA ID, после чего `retry-3` прошел полностью.

## Границы результата

Эти две проверки подтверждают два отдельных поведения закрепленной версии
Juice Shop. Они не являются повторным прогоном полного агента, не изменяют
исходную таблицу 7/27 и сами по себе не пересчитывают Precision, Recall, FPR,
severity, Context Priority или baseline. Для нового значения метрик нужен
полный согласованный benchmark-run с неизменным matcher.

После добавления этих протоколов полный локальный набор: **1443 passed,
29 skipped**; Ruff, `git diff --check` и `python -m app.main` прошли. В журнале
есть только обычные предупреждения deprecation библиотек. Пропуски — условные
интеграции, которые запускаются только при отдельной конфигурации; две новые
Docker-приемки были запущены явно.

Обе проверки добавлены как source-bound operator grants к диагностическому
runner. Их отдельная полная стоимость в текущем окружении — 154 запроса каждая.
Историческая шестипротокольная серия использовала 759 из 1024. Поэтому запуск
обоих новых протоколов поверх всех шести не помещается в тот же лимит; общий
планировщик должен оставить непоместившийся кандидат `review_pending`, а не
превышать лимит или трактовать отсутствие проверки как безопасный результат.
