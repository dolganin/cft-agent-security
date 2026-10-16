# Общий проход готовых проверок Juice Shop — 16 октября 2026

## Результат

На том же замороженном наборе A04 подтверждено **11 из 27 уязвимых случаев**.
Ранее было 7 из 27: прирост 4 случая, или **14,81 процентного пункта Recall**.
Все семь прежних подтверждений сохранены. Новые: изменение чужого отзыва,
NoSQL-селектор отзыва, подделка автора feedback и чувствительное поле `whoami`.

Выполнен один новый проход `fixed_verification_only`: свежий SAST, штатные
source detectors, обычная очередь и зарегистрированные проверки через
Validator → SafeExecutor → persisted execution/audit → Evidence. Модельных
вызовов: **0**. Измерение проверяет текущую цепочку обнаружения и фиксированного
подтверждения; качество самостоятельного исследования LLM здесь не измерялось.

Target: Juice Shop v20.2.0, commit
`5658473cf8814459bf89000ce373b20ed0b4eb37`. Target image, исходники, A04 labels,
разбиение и matcher сохранены. Набор для сравнения: **27 положительных и 8
безопасных original cases**. Остальные шесть записей полного dataset относятся
к другому sample slice и в эти знаменатели не входят. Исторический HOLDOUT
уже использовался при разработке; он не является независимым новым тестом.

## Метрики и сравнение

Старый результат заново пересчитан текущим offline scorer из sealed execution
и audit, затем тем же способом пересчитан новый. Это сравнение двух фактических
сохраненных запусков, а не среднее по нескольким новым повторам.

| Показатель | Раньше | Сейчас |
|---|---:|---:|
| Найдены положительные случаи | 27/27 = 100% | 27/27 = 100% |
| Подтверждены положительные случаи / runtime Recall | 7/27 = 25,93% | **11/27 = 40,74%** |
| Precision подтверждений, сопоставленных эталону | 7/7 = 100% | 11/11 = 100% |
| Ложные подтверждения на 8 безопасных случаях | 0/8 = 0% | 0/8 = 0% |
| Бинарные решения по безопасным случаям | 0/8 | 0/8 |
| Точность среди вынесенных бинарных решений | 7/7 = 100% | 11/11 = 100% |
| Покрытие бинарных решений на всех 35 original cases | 7/35 = 20% | 11/35 = 31,43% |
| Осталось без runtime-подтверждения | 20/27 | **16/27** |
| Precision обнаружения по A04 | 27/28 = 96,43% | 27/28 = 96,43% |
| SAST baseline: найдены положительные случаи | 10/27 = 37,04% | 10/27 = 37,04% |

Ноль ложных подтверждений — наблюдаемый результат при высокой доле abstention:
ни один безопасный случай не получил бинарного решения. Поэтому условная
ошибка **среди решенных безопасных случаев** остается N/A (знаменатель ноль).
Эти данные не доказывают надежное распознавание безопасного кода. На уровне
детекции matcher относит одно наблюдение к безопасному случаю
`JS-SAFE-BIZ-101`: detection FPR = 1/8 = 12,5%; оно осталось неподтвержденным.

Точность severity и Context Priority не измерена: scoring inputs не оценивались
в этом проходе, а у A04 нет независимых CP labels. MTTR не измерен: исправления
в этом запуске не выполнялись. Воспроизводимость независимых полных прогонов
не измерена: новый прогон один. Два поколения внутри отдельных протоколов
проверяют повторяемость этих операций и не заменяют повтор всего benchmark-run.
Свежий baseline здесь только SAST; сравнения с новым DAST-запуском нет.

## Все 27 положительных случаев

`Нет проверки` означает найденный кандидат без принятого runtime-доказательства.
Это не отрицательный вердикт о наличии уязвимости.

| Случай | Раньше | Сейчас | Что подтверждено или чего не хватает |
|---|---|---|---|
| JS-AUTH-001 | confirmed | confirmed | Изменение собственного пароля без повторной аутентификации |
| JS-AUTHZ-001 | нет проверки | нет проверки | Нужен фиксированный протокол anonymous Product PUT |
| JS-AUTHZ-002 | нет проверки | нет проверки | Нужны регистрация одноразового пользователя и независимый readback роли |
| JS-BIZ-001 | нет проверки | нет проверки | Отрицательное количество и расчет суммы в собственной корзине |
| JS-BIZ-002 | нет проверки | нет проверки | Применение контролируемого купона и readback скидки |
| JS-BOLA-001 | confirmed | confirmed | Чтение чужой тестовой корзины |
| JS-BOLA-002 | confirmed | confirmed | Добавление товара в чужую тестовую корзину |
| JS-BOLA-003 | нет проверки | **confirmed** | Чужой scalar review ID: сохраненное изменение сообщения |
| JS-BOLA-004 | нет проверки | **confirmed** | Отзыв A сохраняется с UserId B |
| JS-CAPTCHA-001 | нет проверки | нет проверки | Отдельное свойство раскрытия/повторного использования CAPTCHA не проверялось |
| JS-CODE-001 | нет проверки | нет проверки | Ветка отключена auto-safety закрепленного Docker image; не включать ее ради результата |
| JS-CRYPTO-001 | нет проверки | source-only отдельно | AST подтверждает связь MD5 с хранением пароля; в runtime Recall не включено |
| JS-DATA-001 | нет проверки | **confirmed** | Выбранное поле password содержит хеш тестовой учетки |
| JS-DATA-002 | нет проверки | нет проверки | Нужно определить чувствительные поля metrics и проверить disclosure |
| JS-FILE-001 | confirmed | confirmed | Открытая directory metadata FTP |
| JS-FILE-002 | нет проверки | нет проверки | Нормализация имени файла с контролируемым тестовым файлом |
| JS-NOSQL-001 | нет проверки | **confirmed** | Ограниченный selector изменяет обе собственные тестовые записи |
| JS-NOSQL-002 | нет проверки | нет проверки | Контролируемый набор заказов и проверка order selector |
| JS-PATH-001 | нет проверки | нет проверки | Архивный marker и containment внутри disposable tmpfs |
| JS-RATE-001 | нет проверки | нет проверки | Фиксированный threshold и сравнение forwarding identity keys |
| JS-REDIRECT-001 | confirmed | confirmed | Недопустимое направление redirect; внешний адрес не посещается |
| JS-SQL-001 | confirmed | confirmed | Дифференциальный SQL-протокол поиска |
| JS-SQL-002 | confirmed | confirmed | Фиксированный login SQL-протокол |
| JS-SSRF-001 | нет проверки | нет проверки | Нужен разрешенный локальный sink и доставка marker |
| JS-XSS-001 | нет проверки | нет проверки | Независимый browser marker и безопасный counterpart |
| JS-XSS-002 | нет проверки | нет проверки | Собственный продукт, browser marker и reset |
| JS-XXE-001 | нет проверки | нет проверки | Локальная entity fixture и owned marker |

Итого: 11 runtime confirmed; 15 без зарегистрированного применимого протокола,
включая недоступную CODE-ветку; один CRYPTO случай с отдельным source proof.
Source proof не потерян и не превращен в runtime-подтверждение.

## Исполнение, бюджет и аудит

Новый проход занял **123,472 секунды** вместе с подготовкой; campaign —
95,016 секунды. Получено 95 SAST observations и 41 source-detector observation;
после объединения сохранено 97 canonical candidate findings. Их количество
не равно числу независимых уязвимостей в эталоне.

Запущено 15 verification jobs: 13 с архивным verdict confirmed и 2 inconclusive.
Ровно 11 разных положительных A04 cases получили поддержанные подтверждения.
Две inconclusive directory-проверки (`/.well-known`, `/support/logs`) находятся
вне original positive slice. Две дополнительные confirmed-строки также не
включены в 11: directory metadata `/encryptionkeys` находится вне эталона;
для кандидата в `createProductReviews.ts` update-протокол доказал другое
свойство, поэтому отдельное подтверждение creation-authorship не принимается.

После прогона для последнего случая добавлен source-operation guard: review
update checks принимают первичную находку только из `updateProductReviews.ts`.
Creation/read source files остаются контекстом для fixture. Исправление
проверено против сохраненного ошибочно направленного action: текущий Validator
отклоняет его, остальные B05 actions этого прогона разрешает. Новый полный
target-run после guard не выполнялся; эти сохраненные результаты относятся к
реализации до guard. Результат **11/27** от этого не меняется: спорная строка
не сопоставлена ни одному A04 case.

Стандартный budget runner остается 1024. Для этого прохода оператор явно
задал **1708**: 1696 — сумма резервов восьми готовых fixture protocols,
12 — существующие B01 SQL/directory routes. Схема допускает явный campaign
budget до 2048, каждый research runtime по-прежнему ограничен 256.

Фактически списано **1221/1708** запросов. Накопленная сумма резервов — 1958:
до исправления source-operation guard update-протокол запускался для двух
разных source anchors. Неиспользованный резерв возвращался после полного
учета и принятого terminal Evidence, поэтому накопленные резервы не являются
одновременно занятым бюджетом. Все восемь готовых fixture protocols исполнены;
budget-related pending нет. B05 lifecycle accounting восстановлен из журналов,
сумма списаний совпала с campaign summary. Readiness основного target до
campaign относится к отдельному этапу подготовки.

Все 15 persisted jobs дважды независимо replayed через execution+approval+audit;
результаты совпали с архивными verdicts. Run seal включает 140 файлов.
Cleanup и source integrity подтверждены. Ни один исторический результат или
файл A04 не переписывался.

Проверки финального кода после source-operation guard: **1449 passed,
29 skipped**; Ruff, `git diff --check` и smoke `python -m app.main` прошли.
Пропуски включают opt-in Docker/browser/provider интеграции; новый общий
verification-only запуск, описанный выше, выполнен отдельно и завершен.

## Артефакты и повторение

```text
artifacts/juice-all-ready-verification-2026-10-16/   # единственный новый target-run
artifacts/juice-all-ready-before-score-2026-10-16/   # пересчет прежнего run
artifacts/juice-all-ready-score-2026-10-16/          # новые case/family metrics
artifacts/juice-all-ready-gaps-2026-10-16/           # все 27 cases и 16 пробелов
artifacts/juice-all-ready-comparison-2026-10-16/     # общие метрики и все 35 original cases
```

В score-папках есть summary, observations, runtime-review, case-losses,
family-metrics, DEV/HOLDOUT scorecards и seals. Исходный прежний run:
`artifacts/juice-fixed-source-acceptance-retry-3-2026-10-15`.

Общий handoff:
`artifacts/juice-all-ready-measurement-final-2026-10-16.zip`.
Он включает оба исходных запуска, оба offline score, gap audit, machine-readable
comparison и этот отчет. `source-provenance.json` хранит хеши текущей рабочей
реализации; исполняемый код и окружение в этот архив измерений не включаются.
Код остается в рабочей ветке `codex/juice-shop-plan-recovery`, без нового commit/push.

Новый target-run, только в свежую папку:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m app.research_diagnostic_run \
  --checkout artifacts/benchmark-target/juice-shop \
  --image sha256:73fd92a20ad72cf189bfcda4604196b8476dfad07c54bbf06ec830e3ec0fa7e7 \
  --browser-image sha256:2f553e84f1e6fbccd51a5d5d7efa7af8c4dbe63a202c60efd830c0b9b62b05ea \
  --output artifacts/<fresh-run> \
  --verification-only --max-http-requests 1708 --wall-seconds 1200
```

Offline-пересчет без Docker и provider calls:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m app.research_score \
  --run artifacts/juice-all-ready-verification-2026-10-16 \
  --output artifacts/<fresh-score>
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m evaluation.juice_verification_gaps \
  --run artifacts/juice-all-ready-verification-2026-10-16 \
  --output artifacts/<fresh-gaps>
```

Результат текущего этапа — измеренный рост подтверждений при прежнем полном
знаменателе. Следующие инженерные работы: Product PUT authorization и role
assignment, затем остальные отсутствующие property-specific protocols.
