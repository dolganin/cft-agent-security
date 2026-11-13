# A04. Проверка и заморозка эталона v2

Дата: 12 октября 2026. Входная версия main: `e3e9ec5`.
Цель: Juice Shop v20.2.0, `5658473cf8814459bf89000ce373b20ed0b4eb37`.

## Результат и границы

Заморожены 27 положительных source-reviewed случаев и 14 безопасных контролей.
Это не 116 успешно воспроизведенных уязвимостей и не новый прогон агента.
Эталон не исчерпывает все уязвимости Juice Shop. Около 20 отрицательных случаев
было целевым ориентиром, фактически доказано 14: остальные не добавлены ради числа.

Проведены основной автоматизированный проход по исходникам/контрактам/сохраненным
Evidence и отдельный read-only проход агента Dalton. Независимого человеческого
ревью не было. Это явно записано в `review.yaml`; слово reviewed не означает
человеческое одобрение. В A04 не выполнялись HTTP-проверки, target scripts,
Docker replay, LLM-запросы или benchmark measurements. Перепроверены сохраненные
A03 proofs, digests и execution/audit bindings, а не выполнены новые циклы.

В основную копию репозитория подтянут A01–A03 commit. A05 обнаружен в
`origin/feature/a05-benchmark-v2`; его код не интегрирован и не изменен.
Работа A04 находится в отдельной ветке `codex/a04-freeze-benchmark-v2`.

## Какие знаменатели использовать

| Срез | Уязвимые | Безопасные | Основание |
|---|---:|---:|---|
| Original source/detection | 27 | 8 | Исходники закрепленной версии; некоторые свойства статические |
| Original default-runtime scope | 21 | 3 | Положительные условно исполнимы; отрицательные имеют сохраненный runtime proof |
| Patched controls | 0 | 2 | Отдельные исправленные копии redirect/NoSQL |
| Synthetic controls | 0 | 4 | Отдельные минимальные функции, не Juice Shop runtime |

Два patched случая и четыре synthetic случая связаны с исходными причинами,
поэтому не являются еще шестью независимыми причинами. Внутри оригинала есть
разные свойства общих endpoint/механизмов: root-cause grouping не доказывает
статистическую независимость всех наблюдений. Нельзя смешивать эти срезы в одну
первичную runtime FPR/precision. Для patched/synthetic среза recall без положительных
случаев N/A. Source-only безопасное свойство не означает безопасность всего endpoint.

В оригинальном runtime scope 21 положительный случай остается знаменателем
verified recall, даже если агент не имеет нужной capability. Шесть source-only /
Docker-disabled / fixture-unavailable случаев остаются в detection отчете и видимом
списке исключений runtime scope. Scope закреплен ДО результатов; его нельзя менять
после прогонов, чтобы улучшить показатель. Условная исполнимость не разрешает
новую операцию и не доказывает runtime vulnerability.

## Исправления после второго прохода

Исторические A02/A03 записи и их lock/proofs не переписаны. Уточнения внесены
в новую A04 проекцию и sidecar scope:

1. `JS-FILE-001` теперь относится только к конкретному public `/ftp` mount,
   `server.ts:288–289`. Keys и logs больше не могут дать TP этому случаю.
   Исходная A02 агрегация трех публикаций сохранена как история; еще два mount
   требуют отдельных случаев новой версии, не являются safe или дублями FTP.
2. Redirect control ограничен `isRedirectAllowed:133–139`; NoSQL control —
   post-patch scalar guard/selector:17–25, а не целым файлом. Эти anchors относятся
   к исправленной копии. A05 обязан учитывать sample kind, не матчить их на оригинал.
3. Четыре synthetic control используют четыре отдельных function-level anchors.
4. MD5 case подтверждает слабую конструкцию хранения, не фактическую утечку hash
   и не успешный взлом пароля. Severity ему не назначена без impact metrics.
5. Для arbitrary whoami fields добавлена provenance цепочки login SELECT/User cache.
   Runtime password-hash disclosure в A04 не воспроизводился.
6. Coupon criterion требует собственного тестового basket: нельзя смешивать
   forged coupon с отдельной проблемой доступа к чужому объекту.
7. Stock upper-bound control остается узким safe свойством, не безопасным twin
   всей отрицательной quantity ветки. Отрицательные quantities уязвимы отдельно.

Runtime-proof helper A03.1 получил только переносимый явный `target` при проверке
сохраненных proofs. На чужом компьютере он раньше обращался к зашитому локальному
default checkout даже при переданном другом target. Policy/capabilities не менялись.

## Разметка серьезности и Context Priority

В `rubric.yaml` заморожена узкая экспертная ordinal HIGH рубрика для четырех
source-grounded случаев: двух SQL sinks и двух public authorization/role flows.
Это НЕ официальная severity Juice Shop, НЕ оценка сложности задания и НЕ numeric
CVSS 3.1. Для остальных 37 записей severity N/A; это не LOW и не safe.
Сопоставлять эти четыре labels допустимо только с assessment той же рубрики;
UNASSESSED/N/A не входят в assessed accuracy, но остаются в coverage.

Context Priority N/A для всех 41 записей: независимой разметки бизнес-критичности,
deployment exposure, trust/blast radius для этого стенда пока нет. Не используем
выход нашего ScoringService как его собственный эталон. Accuracy CP сейчас
измерить нельзя. B08 может подготовить независимый контекст и новую версию labels.
MTTR также не измерялся; A04 не вносит исправлений.

## DEV/HOLDOUT и воспроизводимость

A01 seed и helper неизменны. 28 development / 13 holdout cases, включая twins;
27 positives распределены 20/7, 14 controls — 8/6. Twins всегда в одном split.
SQL holdout уже исследовался в историческом v1; Juice Shop публичен. Этот holdout
означает замороженные labels без перенастройки, НЕ доказательство unseen-качества.
Смена seed/rebalance после измерений запрещена.

`dataset.lock.json` связывает corpus, protocol, catalogs, exclusions, reset,
patches, все сохраненные proof/audit records и evaluator/schema helpers.
Любой измененный/пропавший/добавленный input вызывает отказ preflight. Lock
контролирует целостность, а не внешнюю криптографическую подпись; доверенная
версия определяется commit/PR. Исторические v1 и A01 locks не изменены.

```bash
python -m evaluation.benchmark_freeze validate
python -m evaluation.benchmark_freeze validate --target <clean-pinned-Juice-Shop-checkout>
python -m pytest tests/test_a04_freeze.py -q
```

`render --target ...` выводит предложение файлов в stdout, ничего не записывает.
После freeze render отказывает, чтобы исключить случайную перезапись. Изменения
эталона должны выпускаться отдельной v2.1/v2.2/v3 с changelog, не reseal v2.

## Handoff для A05/A06/A07

`ground_truth.yaml` совместим с `BenchmarkDatasetV2` из текущей A05 ветки:
`benchmark.dataset.v2`, status `frozen_a04`, canonical source/HTTP anchors,
sample kind, split, expected labels. A04 не копирует чужие shared schemas и не
создает еще один scorer. `scope.yaml`, `rubric.yaml`, `review.yaml` обязательны,
а не необязательные пояснения: до producer/scoring надо вызвать A04 preflight
и выбрать замороженный scope/split/sample slice. Нельзя просто передать все 41
запись в scorer и назвать результат runtime Juice Shop benchmark.

Truth и oracle/test answers остаются evaluator-only, за пределами target discovery.
Новые permissions, tools, target URLs и ExecutionResult verdicts не добавлены.
Прежде чем запускать A07, нужны приемка A05 evidence/trace/matcher, A06 scanner и
environment locks и настоящий reset. Этот документ не объявляет A07 выполненным.

## Проверки перед передачей

- Полный backend: **838 passed, 17 skipped**, две deprecation warnings, без failures.
- 17 skips: 6 Docker boundary, 1 multi-run, 4 sandbox manager, 1 sandbox runner,
  3 SberLab session, 1 opt-in Stage1 E2E и 1 Stage2 operator prerequisite.
- Ruff для всех tracked Python и новых файлов проходит, `git diff --check` проходит.
- `python -m app.main` завершает детерминированный stub: confirmed, 1 iteration,
  1 Evidence. Это smoke системы, не benchmark measurement.
- A04 preflight с отдельным clean pinned checkout проходит, **114 inputs bound**.
- `ground_truth.yaml` действительно прочитан Pydantic-схемой A05 ветки:
  **41 cases, frozen_a04**. Это проверка формата, не приемка A05 scorer.
- Локальная fixture-копия восстановлена из существующего чистого pinned Git clone;
  scripts/install/build цели на хосте не выполнялись. Новые runtime cycles: **0**.
- Нет изменений в AgentState, production registry, policy, target permissions,
  исторических A02/A03 labels/proofs, v1 или A01 protocol/lock.
