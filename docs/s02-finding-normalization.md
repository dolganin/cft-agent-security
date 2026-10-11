# S02. Общая нормализация и происхождение находок

11.10.2026. Реализовано поверх S01 в рабочей ветке, без слияния в main.
Задача: один узнаваемый случай вместо дублей SAST/Scout, без потери наблюдений
и без опасного объединения разных дефектов.

## Что изменено

`security/source_paths.py` — общий нормализатор. Windows separators и `./`
приводятся к POSIX-relative spelling. Регистр и dotfiles сохраняются.
Traversal отклоняется, а не очищается; drive-relative пути, alternate streams,
пустые/control-character пути запрещены. Absolute paths допускаются только при
проверке containment относительно доверенного корня. Отвергаются symlinks файла
и родительских директорий, даже если они ведут внутрь репозитория.

Офлайн Windows/UNC fixture допускает лексическую проверку относительно Windows
корня на другой ОС, но не чтение чужого filesystem. Реальный runner использует
native trusted target root и физическую проверку containment.
Docker Semgrep `/src` переводится в host-relative путь только когда runner
действительно выбрал фиксированный Docker fallback. Модель не задает этот mapping.

`sast/identity.py` — единый алгоритм семейства, fingerprint и dedup.
Ключ включает service, family, normalized file, точный диапазон строк, digest
байтов файла, digest окна и columns при наличии. Прочитывается не более 1 MiB
на файл; anchor не более 160 строк. Это только ограниченное чтение/хеширование,
никакого исполнения исходников. При недоступном/большом/бинарном файле provenance
явно `location_only`, а не доказанно source-bound.
Без прочитанного anchor не объединяются разные источники: допускается лишь повтор
идентичного наблюдения того же источника/правила/описания.

Точные совпадения одного диапазона объединяются, SAST остается основным источником.
Разные диапазоны, сервисы, семейства, версии файла или scanner columns остаются
отдельными. Когда на одной строке несколько точных scanner spans, Scout без columns
не может выбрать один: кандидат сохраняется отдельно. Находки без line anchor
не объединяются по похожему названию. Повторная dedup идемпотентна.

## Совместимый контракт

Новые классы находятся в `schemas/finding.py` и экспортируются из `schemas`:

- `FindingObservation`: source/source_id/rule_id, оригинальное spelling файла,
  title/description, строки/columns, исходная severity, rationale и provenance_paths;
- `FindingProvenance`: версия 1.0, family, fingerprint, normalized_file,
  file_sha256/anchor_sha256, anchor_status, aliases и observations;
- `Finding.provenance`, `ReportFinding.provenance`, `ApiFinding.provenance` optional.

Нет новых обязательных полей для старого Finding/FinalReport. Архивы читаются
как прежде. Исторический primary ID сохраняется; для новых Semgrep результатов
ID использует канонический путь. Оригинальный ID находится в aliases.
Если разные дефекты раньше имели одинаковый rule:path:line, output IDs получают
суффикс fingerprint, чтобы не перезаписать друг друга в SQLite/report index.
Поиск JsonFindingRepository поддерживает aliases; неоднозначный alias отклоняется.

Объединение не теряет описания и rationale второго источника. Модельные severity
остаются наблюдением источника, не CVSS и не measured severity основного Finding.
Наблюдение поиска не является `Evidence`, не дает confirmed или execution approval.

## Потребители

Semgrep runner/CLI/pipeline сохраняют raw JSON и normalized findings, а summary
различает raw_total, duplicates и итоговые случаи. Existing-findings input
нормализуется в отдельный output, не переписывая пользовательский архив.
Scout merge и source corpus используют ту же нормализацию. Artifact registry
больше не регистрирует linked paths; legacy verification metadata file:line
читается по canonical spelling, без изменения разрешенных capabilities.

Report builder и static-only report сохраняют provenance. API report возвращает
публичную копию, SQLite index получил совместимую nullable `provenance_json` migration.
Оригинальные абсолютные пути остаются в локальном отчете; API normalizes их
в original_file/source_id/aliases. Старые SQLite строки имеют provenance=null.
Evaluator и PR path reader используют общий normalizer. Исторический PR fingerprint
между Git refs намеренно остается отдельным алгоритмом: его миграция не выдается
за завершенную в S02.

## Фикстуры и проверка

`contracts/examples/s02/paths.json` содержит реальные относительные пути из
сохраненных SberLab SAST и Juice Shop Scout artifacts и явно отмеченные Windows,
POSIX, dot-prefix/UNC spelling variants. Это не новый прогон benchmark.
`tests/test_finding_identity.py` проверяет containment, case/dotfiles, symlinks,
SAST+Scout merge, два sinks на строке, порядок входов, разные диапазоны/сервисы/
семейства/версии, idempotence, legacy aliases и неоднозначность, report/API и
SQLite migration. Старый тест пересечения диапазонов изменен на точное совпадение;
новый тест отдельно доказывает, что overlap больше не объединяется.

## Что не обещает S02

Fingerprint привязан к версии файла и строкам. Он не доказывает, что sink достижим,
не отслеживает автоматически перемещение строк между ревизиями и не разрешает
runtime проверку. Git commit/tree digest не подставляются по текущему HEAD как
будто они описывали историческое сканирование. Existing provenance с изменившимся
file digest отклоняется: нужен повторный scan, не молчаливый rebind.

Семантические bindings, relocation, digest перед действием и выбор разрешенной
capability — S03 после K02/R01. Здесь сохраняется прежняя цепочка Validator ->
Executor -> Evidence. Ни новый источник, ни fingerprint не расширяют target scope.

## Результаты приемки

Полный pytest: 554 passed, 18 skipped (нет настроенных target paths, pinned images
или opt-in integration prerequisites). Добавлено 40 тестовых случаев S02.
Ruff: все tracked Python файлы и новые файлы проходят. Детерминированный
`python -m app.main` завершился с confirmed и одним Evidence. Нового live Juice Shop
benchmark в этой задаче не выполнялось, улучшение precision/recall не заявляется.

Read-only проверка архивов: четыре raw SberLab SAST результата дали четыре
нормализованных случая с сохраненными путями; 12 Juice Shop Scout кандидатов дали
12 случаев и 12 наблюдений. 18 сохраненных presentation reports читаются текущим
FinalReport. Четыре более старых `artifacts/security-pipeline/reports` используют
прежний Evidence с details и без обязательных action/observation/scope: они уже
несовместимы с текущим Evidence до S02. Эти архивы не переписывались; их миграция
требует отдельного reader с явно legacy/непроверенной семантикой, а не выдуманных
execution approvals или runtime Evidence.
