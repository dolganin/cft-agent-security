# A06. Воспроизводимые SAST и DAST baseline

Роман. Ветка: `SAST-and-DAST-baseline`. Основа: main `8f5b6d3`.

## Что реализовано

Отдельный измерительный CLI `python -m app.scanner_baseline` запускает Semgrep
и OWASP ZAP без Scout, LLM, агентной фильтрации, contextual scoring или изменения
production pipeline. A06 не добавляет агенту execution capability и не изменяет
Validator, Executor, Evidence, FinalReport или CI Gate. Scanner alerts — это
обнаружения, а не evidence-backed `confirmed`.

Конфигурация: `benchmarks/baselines-a06-v5/profile.yaml`. SHA-256 freeze связывает
profile, ruleset, provenance, лицензию, адаптеры, driver и CLI. Source/config hashes
нормализуют CRLF → LF; seal результатов связывает точные байты. Образы запускаются
только по repository digest, без автоматического pull. Пересборка ruleset и freeze
не перезаписывают существующие файлы.

SAST: Semgrep CE 1.174.0. Используются 310 security rules из upstream
`semgrep/semgrep-rules` commit `9bbf021d0acffa3095fcffd17b2bc7787eb4796d`:
security YAML для JavaScript, TypeScript, HTML, JSON, YAML, Dockerfile и generic.
Тестовые fixtures upstream исключены. Patterns и metadata сохраняются; ID получают
префикс исходного пути для устранения коллизий. Список исходных файлов, SHA-256,
rule IDs и лицензия сохранены. Это весь выбранный языковой security pack, а не все
возможности коммерческого Semgrep: нет Pro/interfile analysis, SCA или secret engine.
Ruleset не выбирается по ожидаемым ответам Juice Shop, dev/holdout или результатам.

DAST: OWASP ZAP 2.16.1 с поставляемыми в pinned image active/passive rules и
одним Firefox headless AJAX spider. `-silent` запрещает фоновые обращения и обновления.
`dast/versions.json` сохраняет реальные версии ZAP, add-ons и включённых правил.
Nuclei не подключён: A06 требует один сопоставимый DAST, исторический план
предусматривает Nuclei после устойчивого ZAP.

## Scope и бюджеты

Цель: Juice Shop v20.2.0, Git `5658473cf8814459bf89000ce373b20ed0b4eb37` и
официальный образ из A01/существующего demo Compose. У исходной копии проверяются
commit, clean status и байты каждого tracked файла; после запуска — неизменность.
Target scripts не выполняются на хосте.

Каждая DAST-попытка создаёт отдельный target container и внутреннюю Docker network;
нет published ports, host network, host gateway, Docker socket или произвольного
URL. ZAP API доступен только на loopback внутри scanner container. Выход в интернет
во время scan отсутствует. SAST работает networkless с read-only source/rules mounts
и tmpfs. Исходники передаются tar-снимком с проверенными хешами через фиксированный
stager в отдельный Docker volume; scanner монтирует volume read-only. Это устраняет
медленные чтения тысячи файлов через Windows bind mount. В volume только tracked
файлы, без host `.git` и credentials. Stager не запускает target code. Volume удаляется
после сканирования. API/LLM credentials в subprocess/scanner не передаются.

| Ограничение | Значение |
|---|---:|
| Semgrep wall time | 600 s |
| Готовность target / ZAP | по 180 s |
| Traditional spider | 60 s |
| AJAX spider | 60 s |
| Active scan | 180 s |
| Ожидание passive queue | 180 s |
| Максимальный passive response body | 256 KiB |
| Scanner CPU / RAM | 2 CPU / 2 GiB |
| Target CPU / RAM | 2 CPU / 768 MiB |
| Scanner PID | SAST 256, ZAP 512 |
| Alert export | 10 000; превышение — technical error |

Роль первой замороженной конфигурации — **anonymous**. Авторизованные, admin,
cross-user, бизнес-логические и OAST проверки не заявляются. Seeds — обычная
публичная навигация, без ground truth, challenge-answer payloads и hidden labels.
Цель и образ одинаковы с агентным baseline; различия discovery/ролей/бюджетов нужно
сохранять в A07 manifests, а не называть охват идентичным.

Traditional/AJAX/active scan ограничены временем. Остановка по установленному
бюджету — видимое ограничение покрытия, а не доказательство полноты. Ошибки API,
невозможность стартовать browser/target, недренированная passive queue, отсутствующие
артефакты и Semgrep parser/rule errors делают попытку `TECHNICALLY_INVALID`.
Частичные observations сохраняются. Предупреждения Semgrep уровня warn: Syntax error (code 3), PartialParsing (code 3), Timeout отдельного правила (code 2) сохраняются целиком как coverage_limitations. Они дают COMPLETED_WITH_LIMITATIONS при успешном процессе и ненулевом scanned files; неизвестные diagnostics остаются техническими отказами. Это явно зафиксированная политика измерения: знаменатель original cases не сокращается, неполное покрытие не считается полным.
Большие response bodies пропускаются passive body analysis; это ограничение
зафиксировано в profile/coverage, а не скрыто ради успешного статуса.
Semgrep default ignores и исключения node_modules/dist/build остаются видимыми.

## Подготовка и запуск

Python с обычными project dependencies, Git и работающий Docker Engine. Отдельные
Semgrep CLI, Java, Firefox и ZAP Desktop на хосте не нужны: сканеры в Docker.

Нужен чистый LF checkout цели вне исходников агента. Если он уже подготовлен,
повторно clone не выполнять:

```powershell
git clone --filter=blob:none --no-checkout https://github.com/juice-shop/juice-shop.git artifacts/benchmark-target/juice-shop
git -C artifacts/benchmark-target/juice-shop -c core.autocrlf=false checkout --detach 5658473cf8814459bf89000ce373b20ed0b4eb37
python -m app.scanner_baseline validate
python -m app.scanner_baseline preflight --provision-images
python -m app.scanner_baseline run --output artifacts/a06/attempt-001
```

`--provision-images` явно разрешает Docker pull трёх закреплённых образов. Обычные
validate/preflight/run ничего не скачивают. Выход `0` означает completed acceptance,
`2` — технически невалидную попытку. Findings сами по себе не превращают exit в FAIL:
это scanner baseline, не production Gate.

На Windows возможны старые CRLF checkout bytes файлов, уже связанных raw-byte
lock A04. В таком случае восстановить LF-байты исходных файлов, проверяя совпадение
с существующим lock; не перезаписывать A04/protocol/dataset lock ради прохождения.

## Артефакты и A05

```text
manifest.json                      # attempt/retry IDs, input hashes, image IDs, errors
resources.json                     # только ресурсы этой попытки
sast-resources.json                # stager/scanner containers и source volume
sast/source.tar                    # неизменяемый tracked source snapshot
sast/raw.json                      # полный JSON Semgrep
sast/coverage.json                 # scanned paths, parse errors, exclusions
sast/stdout.log, stderr.log
dast/raw.json                      # сырые ZAP alerts
dast/coverage.json                 # стадии, seed responses, URLs, ограничения
dast/urls.json                     # полный список наблюдённых target URLs
dast/versions.json                 # версия, add-ons, active/passive scanner inventory
dast/zap.log, target.log
sast-observations-v2.json
dast-observations-v2.json
union-observations-v2.json
report.md
seal.json
```

Адаптер экспортирует JSON `BenchmarkObservationV2` из A05. Для Semgrep — настоящий
relative file/line range; для ZAP — настоящий HTTP method/path/parameter без
выдуманного source file или строки. CWE-family mapping явный, версионированный,
независимый от эталона; неизвестные/неоднозначные family остаются scanner IDs.
Scanner severity не выдаётся за независимый CVSS или рубрику A04.

Объединение сохраняет оба типа наблюдений. Дедупликация по эталонному случаю —
задача A05; суммировать два TP для одной причины нельзя. Все observations имеют
`verification=not_run`, `evidence_backed=false`: ZAP confidence не заменяет
Validator/Executor/persisted Evidence.

После интеграции A05 в текущую ветку доступна отдельная офлайн-команда:

```powershell
python -m app.scanner_baseline score --artifacts artifacts/a06/attempt-001 --output artifacts/a06/score-001
```

Она проверяет seal, A04 lock и вызывает существующий A05 `score_v2` для SAST,
DAST и union. Никаких LLM или повторного scan. При отсутствии A05 завершается
явной ошибкой, не подменяя оценщик локальной копией. Original source/detection
scope: 27 positives + 8 original controls. Patched/synthetic twins этим runner
не исполняются и не входят в его знаменатель. Primary runtime verification
metrics по одним scanner detections не заявляются. Dev/holdout сохраняются в A04;
для формальной серии A07 нужны отдельные срезы A05.

## Повторяемость и история

Каждый run требует новую output directory; retries указывают
`--retry-of <attempt_id>`. Старые ошибки, logs и seals не удаляются. Cleanup
ограничен UUID/label конкретной попытки, без Docker prune. Полный код/resources
для аварийного operator cleanup записан в manifest/resources.

A06 acceptance показывает работоспособность scanner integration. Три настоящих
независимых запуска каждой сравниваемой конфигурации, агрегирование precision,
recall/FPR и передача исходных метрик — A07/A08. Успешный короткий acceptance
не закрывает эти задачи.

Источники интерфейсов: [Semgrep CLI](https://semgrep.dev/docs/cli-reference),
[ZAP API](https://www.zaproxy.org/docs/api/),
[ZAP Docker](https://www.zaproxy.org/docs/docker/about/).


## Приёмка и изменение политики diagnostics

История неуспешных попыток и предыдущая строгая проверка сохранены в [журнале](a06-review-2026-10-12.md). Версия v5 исправляет классификацию warning diagnostics, не меняя цель, ruleset, исключения или бюджеты. Известные предупреждения парсера и таймаут отдельного правила показывают пределы выбранного инструмента, а не сбой запуска; raw errors не удаляются. Новая конфигурация и код заморожены до повторного полного запуска.

## Итоговая приёмка v5

12 октября 2026: a06-458adfbadd1c4f1e, 262.64 s, COMPLETED_WITH_LIMITATIONS.
94 SAST, 491 DAST, 585 union observations. Это detections, не TP или confirmed.
SAST: 310 выбранных правил, 302 применены к 1027 файлам; 56 warning diagnostics
сохранены полностью. ZAP: traditional/AJAX/active/passive завершены, 234 AJAX
results, 164 URL, passive_remaining=0. Технических отказов нет. Original unchanged
и cleanup complete проверены. Ограничения anonymous, body size и time budgets
остаются действующими даже при complete=true для стадий.

[Архив всех raw результатов, source snapshot, logs, seal и проверок](../benchmarks/baselines-a06-v5/acceptance/a06-458adfbadd1c4f1e.zip)
и [краткий manifest с SHA-256 архива](../benchmarks/baselines-a06-v5/acceptance/summary.json)
хранятся в ветке. В ZIP: attempt/ — неизменённая sealed попытка;
a05-contract-scores/ — три отдельных результата оценщика;
checks/ — проверочный скрипт и фактические test logs. Архив около 17 MB включает
исходный snapshot для проверки полного seal. После распаковки можно проверить
каждый SHA-256 из attempt/seal.json. Сам seal не является цифровой подписью.

Реальные exports валидированы и раздельно посчитаны неизменённым A05 score_v2
из commit 26ff8582601f1c92f58b476ebf726d99ca7eac30. Проверочный скрипт в архиве
читает два модуля из этого Git commit; он не включает и не интегрирует чужую ветку.
Штатная score-команда доступна после интеграции A05. Знаменатель — 35 original
cases; scanner warnings не исключают случаи. Адаптеры и данные для A05 готовы.
A07 с тремя независимыми повторами и итоговым сравнением не выполнен этой приёмкой.

Проверки: 43 A06 tests passed; полная серия 876 passed, 20 skipped, 2 failed.
Два существующих Windows failures: test_trusted_docker_root_translation_is_explicit
и test_provenance_reaches_report_and_public_api_without_host_path в
tests/test_finding_identity.py. Они не изменены А06; полный pytest log включён.
Пропуски связаны с POSIX/symlink и opt-in target/Stage1 integrations.
Ruff и python -m app.main прошли. Merge требует отдельного решения двух failures.
