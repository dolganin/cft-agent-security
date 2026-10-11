# A01 — протокол измерений v2

Источник истины: [protocol.yaml](../benchmarks/juice-shop-v20.2.0-v2/protocol.yaml),
Pydantic-контракт `BenchmarkProtocolV2` и SHA-256
[protocol.lock.json](../benchmarks/juice-shop-v20.2.0-v2/protocol.lock.json).
[README](../benchmarks/juice-shop-v20.2.0-v2/README.md) объясняет те же правила.

v2 фиксирует правила до измерений. Исторический v1, его ground truth, digest,
scorecard и sealed результаты Stage 2 сохраняются без изменений как development/
regression база. Его detection precision не переименовывается в verification
precision. Производственное поведение Pentester не менялось.

Один case — одна независимая security root cause. `independence_group` объединяет
SAST/Scout наблюдения, caller/helper, допустимые anchors и связанные безопасные
варианты. Одна причина даёт максимум один положительный case в срезе и один TP;
один finding — максимум один primary match. Дополнительные наблюдения являются
duplicates. Original/patched/synthetic и DEV/HOLDOUT показываются отдельно.
Неразмеченные находки остаются outside_ground_truth/unreviewed с артефактами и
счётчиками, без участия в TP/FP/TN/FN и основной precision.

| Основная метрика | Числитель | Знаменатель |
|---|---|---|
| confirmed_precision | Верные доказательные CONFIRMED positives | Все доказательные CONFIRMED labeled cases |
| supported_verified_recall | Верные доказательные CONFIRMED positives | Все размеченные positives в оцениваемой области |
| false_confirmation_rate | Ложные доказательные CONFIRMED negatives | Все размеченные negative controls |
| answered_accuracy | Верные CONFIRMED positives + REJECTED negatives | Cases с доказательным бинарным решением |
| decision_coverage | Cases с доказательным бинарным решением | Все размеченные cases |
| abstention_rate | Cases без доказательного бинарного решения | Все размеченные cases |

Нулевой знаменатель — `null` / N/A. Detection TP/FP/FN/TN, precision, recall и F1
остаются отдельной диагностикой прежнего scorer. Severity/Context Priority
оцениваются отдельно, только по независимой reviewed rubric, с assessed coverage;
нет разметки или оценки — N/A. Новый CVSS не реализован.

INCONCLUSIVE, UNSUPPORTED, TIMEOUT, POLICY_BLOCKED и CASE_LEVEL_TECHNICAL_ERROR —
отдельные причины abstention. Также явно сохраняются not_detected, not_run,
invalid_evidence и conflicting_evidence. Они не означают REJECTED. Отсутствие
finding на отрицательном контроле даёт detection TN, но не доказательное rejection.
Оба бинарных вердикта требуют совпадающего high/medium Evidence и persisted
execution/audit binding. Противоречащие бинарные Evidence дают abstention.

Run-level техническая невалидность (`TECHNICALLY_INVALID`) исключает run из
security metrics; попытка остаётся в логах, артефактах, aggregate и technical
failure rate. Case-level сбой остаётся abstention этого case. Runtime-сбой не
меняет detection FN. Каждая сравнительная конфигурация требует 3 независимых
настоящих runs. Все исходные invalid attempts и retries сохраняют attempt ID,
reason/error/`retry_of`; неполная серия не выдаётся за три успешных runs.

Split детерминирован: SHA-256 от точного UTF-8 `seed + NUL + independence_group`;
development при `unsigned_hash * 100 < 70 * 2**256`, иначе holdout. Seed закреплён
в YAML. Порядок cases и добавление новых групп не меняют существующее назначение.
Vulnerable/patched/synthetic twins одной причины остаются вместе. Фактическое
распределение семейств публикуется; seed и split не подстраиваются под score.
Известная публичность Juice Shop ограничивает выводы о переносимости holdout.
Truth/split/protocol metadata не передаются Scout/Agent/LLM/ActionProposal/
production TargetProfile; тесты проверяют существующие allowlist-границы.

Заморожены: Juice Shop v20.2.0, commit
`5658473cf8814459bf89000ce373b20ed0b4eb37`; NSU/Qwen3.8-27B, low reasoning,
temperature 0.1, 8192 tokens, LLM timeout 55 с; Scout 2 turns / 4 candidates /
160000 символов / 60 с; Agent 120 с / 2 iterations. Executor: 5 с wall / 2 с CPU /
256 MB / 1048576 file bytes / 8 processes / 16384 output bytes / 1 run на action /
1 concurrent run. Полные hardcoded read/index/search/probe лимиты, immutable images
и digests текущих baseline inputs — в YAML. Значения взяты из реального v1 config,
sealed manifest и текущего adapter/defaults; секреты отсутствуют.

После freeze изменение требует отдельной версии v2.1/v2.2/v3, changelog, причины
и нового digest; старые locks/results не перезаписываются. После обнаружения
новой настоящей vulnerability outside-ground-truth меняется только следующий
dataset. Полный dataset lock появится в A04; scanner versions/config — A06.
Новые сравниваемые конфигурации сохраняют метрики протокола, но фиксируют свои
producer manifests; они не выдаются за исходную baseline.

Проверка A01: `python -m evaluation.benchmark_protocol`. Ошибка schema, lock или
baseline останавливает эту проверку до producer calls. Будущий v2 preflight обязан
использовать этот gate и отдельно проверять A04/A06 locks. Основные формулы v2
реализованы как reducer существующих matches в `evaluation/benchmark.py`;
нового detection scorer нет. Исторический adapter подтверждает Evidence только
для CONFIRMED: адаптация REJECTED и интеграция реальных v2 runs относятся к A05.

Сейчас нет настоящего v2 ground truth, каталога уязвимостей, отрицательных
контролей, новых anchors/matcher, DAST, изменений SAST/Scout/capabilities или v2
измерений. **Следующими A02 и A03 могут выполняться параллельно.** Они не начаты
в рамках A01. Внешние библиотеки и сторонние модули не подключались.

Проверки 11 октября 2026:

```powershell
python -m evaluation.benchmark_protocol
python -m pytest tests/test_a01_measurement_protocol.py tests/test_stage2_benchmark.py -q
$env:CFT_AGENT_MODE='stub'
python -m pytest -q -rs --junitxml=artifacts/a01-checks/backend.xml |
  Tee-Object -FilePath artifacts/a01-checks/backend.txt
python -m ruff check .
git diff --check
python -m app.main
python artifacts/a01-checks/verify_head_baseline.py
```

A01: **36 passed**; Stage 2: **50 passed** (совместная команда: **86 passed**).
Protocol/schema/lock/baseline check, Ruff, diff check и stub `app.main` прошли.
Полный backend: **691 passed / 25 skipped / 3 failed**. Сохранены
[JUnit](../artifacts/a01-checks/backend.xml) и
[вывод backend](../artifacts/a01-checks/backend.txt).

Все три failures находятся в неизменённом `tests/test_finding_identity.py`:
`test_portable_path_fixtures_preserve_case_and_dotfiles[case7]` (Windows UNC
PermissionError), `test_trusted_docker_root_translation_is_explicit` (POSIX `/src`
на Windows), `test_provenance_reaches_report_and_public_api_without_host_path`
(literal Windows path сравнивается с JSON-escaped текстом). Контрольный запуск с
исходными `schemas/benchmark.py` и `evaluation/benchmark.py` из HEAD `5f7238d`,
без нового A01 test module: **655 passed / 25 skipped / те же 3 failed**.
Другие production/test файлы не менялись. Исправление этих production path/tests
не включено в A01; полный suite не объявляется зелёным и merge не выполнялся.

Skips: 16 Docker/target/image/opt-in integrations, 8 Windows symlink checks,
1 POSIX resource-limits check. Stage 1 real Docker E2E и frontend checks не
запускались: production pipeline, frontend и shared API schemas не затронуты.

Raw SHA-256 всех пяти файлов исторической benchmark-v1 директории сохранены
в baseline protocol и проверены тестом; `ground_truth.yaml` сохраняет digest
`3a13a0a41d5fd86d4ab75e23dbc7a61cc81439f034a574b9341a369c82b1aafe`.
Сравнение до/после подтвердило byte-identical сохранность всех **164** файлов
исторических v1 runtime artifacts, включая sealed runs:
[проверка сохранности](../artifacts/a01-checks/v1-preservation.json).

**A01 COMPLETE:** protocol, metrics, split, lock и regression tests готовы;
общие существующие Windows failures явно отмечены. Настоящий scored v2 benchmark
не запускался; A02/A03 не начаты.
