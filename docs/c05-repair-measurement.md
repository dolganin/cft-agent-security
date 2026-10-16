# C05 — повторяемые измерения исправлений

Владелец: Роман. База: `351d6dc`, C01–C04 в main. Реализация и измерения
выполняются в `feature/repair-measurement`. Это отдельный fix-срез сохранённого
B09, а не новый поиск, независимый holdout или обещание исправить все классы.

## Протокол до первого запроса

`python -m app.repair_measurement` фиксирует protocol.json, его SHA256 и полную
копию B09 до вызова LLM. Протокол содержит commit реализации, immutable fix image,
исходный commit, eligibility и шесть слотов в неизменном порядке:

1. SQL search, redirect allowlist — повтор 1.
2. SQL search, redirect allowlist — повтор 2.
3. SQL search, redirect allowlist — повтор 3.

Каждый слот вызывает существующий C04 с реальным ProviderFailoverClient:
`nsu:qwen3.8-flash-next`, reasoning low, до 3 попыток и 900 секунд рабочего
бюджета. Cleanup остаётся обязательным и может увеличить итоговое время.
Новые копии/сессии, штатные native tests, защищённый C03 security contract,
независимые проверки, Validator/Executor/audit и source integrity не меняются.
Одинаковый patch останавливает C04. Начатый слот нельзя заменить или незаметно
перезапустить. Техническая ошибка не исключает слот из знаменателя.

Eligibility — два уникальных benchmark cases из пяти evidence-backed confirmed
cases B09. SQL search имеет один finding, redirect — несколько observations
одного случая; это не дополнительные независимые случаи. Шесть категорий
`ineligible` C01 не являются шестью подтверждёнными уязвимостями.
Case mapping применяется только оценщиком. LLM не получает labels или oracle.

## Время и неуспехи

Основная лабораторная метрика начинается, когда C05 принимает уже подтверждённый
вход перед вызовом C04, и заканчивается после независимого replay сохранённого
результата. Она включает генерацию, все повторы, сборку, тесты и cleanup.
Это **confirmed-input → independently verified patch**, не verifier duration.

Отдельно сохраняется время от первого свежего BEFORE confirmed в этом слоте
до того же финала. Оно исключает первоначальную генерацию и не заменяет основную
метрику. Третье поле — календарное время от исходного подтверждения B09; оно
включает простой между этапами и не используется как лабораторная скорость.
Эксплуатационный и исторический MTTR остаются N/A: исправления не принимались
и не внедрялись в реальную эксплуатацию.

Среднее/медиана времени verified patch считаются только по успехам с указанием n.
Все длительности неуспехов сохраняются отдельно; им нельзя присвоить время
устранения или убрать их из verified/eligible. Регрессии считаются по попыткам;
история каждого слота показывает генерацию, verifier, retry/stop и cleanup.
NOT_FIXED означает отсутствие доставленного verified patch, а не обязательно
доказанное сохранение эксплуатации уязвимости. Technical/Interrupted/Not-run
не смешиваются с этим результатом.

## Воспроизведение

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m app.repair_measurement --target artifacts/benchmark-target/juice-shop `
  --output artifacts/c05-new-series --bundle artifacts/c05-new-series.zip

# После извлечения полного пакета в новый каталог:
python -m app.repair_measurement --replay --output artifacts/c05-extracted
```

Новая серия требует provisioned C03 images, чистый закреплённый target и локальный
provider key; provisioning выполняется отдельно. Replay не требует Docker, LLM
или checkout цели, но требует защищённых C01/C03 файлов репозитория и исходного
B09 ZIP в `artifacts/handoffs/b09-single-2026-10-15.zip`. Полный пакет содержит его
точную копию `b09-full-search.zip`; при переносе восстановить только отсутствующий
файл по этому пути, предварительно сверив SHA256 протокола. Исторический файл
с другим digest нельзя перезаписывать или принимать как совместимый.

Replay проверяет внешний seal, сохранённый протокол, полный B09/C01 replay,
каждый C04/C03 receipt, model/proposal/source/image/route binding и заново считает
метрики. Plain SHA256 seals доказывают согласованность байтов, не подпись
провайдера или независимую аттестацию часов/бинарного образа.

Полный локальный пакет содержит исходные B01 helper snapshots с учебным seeded
private-key fixture Juice Shop. В Git публикуется явно обозначенная проекция;
она не выдаётся за полный replayable пакет. Полные originals сохраняются локально.

## Итог серии 16 октября 2026

Серия: `artifacts/c05-series-final-2026-10-16`. Протокол и шесть слотов заморожены
commit `adff663` до первого запроса этой серии. Последующие изменения усиливают
офлайн-проверку отчёта, не меняя C04/C03, выбор случаев, runtime, бюджеты или
измеренные исходы. Все шесть запусков выполнены реальным NSU provider; reference
diff и IntegrationPatchClient не использовались.

| Показатель | Результат |
|---|---:|
| Eligible / confirmed unique cases B09 | **2/5, 40%** |
| Verified / eligible case-runs | **6/6, 100% в этой серии** |
| SQL / redirect успешных повторов | 3/3 и 3/3 |
| Реальных LLM-попыток / verifier запусков | 6 / 6 |
| REGRESSION attempts / NOT_FIXED / technical / interrupted / not-run | 0 / 0 / 0 / 0 / 0 |
| Confirmed-input → verified patch: n, mean, median | 6; **233.273 с**; 230.945 с |
| То же время, min–max | 165.758–302.837 с |
| Fresh BEFORE → verified patch: mean | 112.689 с |
| Historical/production MTTR | **N/A** |

Для каждого успеха BEFORE confirmed, AFTER rejected, обязательные source/HTTP/
functional/build/startup/smoke gates, original integrity и cleanup подтверждены
сохранённым C03 и независимым C04 replay. Raw native failures двух устаревших
redirect assertions не спрятаны: их учитывает неизменённый защищённый C03 contract.
Ноль REGRESSION не означает ноль raw native assertion failures.

В новой фиксированной серии неуспехов не наблюдалось. Для диагностики отчёт
сохраняет **отдельный реальный исторический неуспех C04**: redirect REGRESSION,
feedback, повторный одинаковый patch и завершённый NOT_FIXED/duplicate_patch.
Причина native process failure не приписывается патчу; canonical AFTER там не
достигнут. Этот случай не подмешан в знаменатели или latency новой серии.
Также сохранён подготовительный C05 сбой создания каталога receipts до первого
C04/LLM вызова: 0 provider calls, 0 измеренных попыток. Он не скрыт и не представлен
как заменённый неудачный measured slot.

Результат описывает два известных DEV случая и три повтора. Он не является
100% repair rate всех классов, unseen holdout, статистической оценкой обобщения
или повышением B09 Recall. B09 по-прежнему содержит 13/27 найденных и 5/27
подтверждённых случаев; его полный неизменный поиск включён в пакет отдельно.

Публичные данные: [таблица](evidence/c05/report.md), [метрики](evidence/c05/measurement.json),
[CSV](evidence/c05/slots.csv), [raw native tests и gates](evidence/c05/native-and-gates.json).
Полный локальный ZIP: `artifacts/c05-series-final-2026-10-16.zip`; его SHA256,
исходный seal и проверка replay перечислены в `docs/evidence/c05/delivery.json`.
SQL ZIPs в публичной проекции — полные отдельные C04 runs; публичная проекция
всей серии не заменяет полный ZIP с redirect source и B09.

Проверки: полный pytest **1610 passed, 32 skipped**, отдельно C05 **25 passed**;
полный Ruff и `python -m app.main` прошли. Пропуски Windows/opt-in перечислены
в сохранённом логе. Два offline replay полного пакета одинаковы; subprocess,
Docker и provider calls запрещены при этой проверке. Сами измеренные originals
и исторические C01–C04 artifacts не переписывались.
