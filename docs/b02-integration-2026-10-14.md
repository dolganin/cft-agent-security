# Приемка B02 после исправлений, 14 октября 2026

Интеграция ветки `feature/b02-sast-expansion` (`064bc4e`) с `main` (`1c7a52b`).
Семь локальных правил и закрепленный профиль сохранены. Исправлены три замечания
ревью: проверка эталона, сохранность артефактов и порядок импортов.

## Исправления

- До сканирования и пересчета вызывается каноническая проверка замка A04.
  Загруженные байты `ground_truth.yaml` дополнительно проверяются по SHA-256;
  статус должен быть `frozen_a04`, target commit должен совпадать с профилем.
  Скрипт больше не присваивает произвольному dataset статус замороженного.
- Любой запуск требует новой папки вывода. `--reuse-raw INPUT_DIRECTORY`
  читает сохраненный manifest, проверяет profile/config, snapshot, raw JSON
  и stderr, после чего копирует исходные данные в новую папку. Исходные результаты
  не перезаписываются. Manifest пересчета содержит ссылку и SHA исходного manifest.
- Ruff исправлен в `app/pipeline_run.py` и `tests/test_sast_profiles.py`.

## Проверки

- Целевые тесты B02 и SAST: **28 passed**, включая реальные проверки Semgrep
  1.174.0 на положительных и отрицательных JS-фикстурах всех семи правил.
- Полный pytest объединенной реализации: **1042 passed, 18 skipped**.
- Ruff для исходников и тестов, а также скрипта B02: passed.
- `CFT_AGENT_MODE=stub python -m app.main`: один шаг, одно Evidence, confirmed.
- Проверка whitespace исходников и документации: passed. Исходный stderr Semgrep
  содержит пробелы форматирования; его байты сохранены вместе с SHA-256.
- Новые регрессии проверяют отказ при измененных байтах эталона, незамороженном
  статусе, несовпадающем target, ошибке канонического замка, существующей папке
  вывода, вложенном выводе и подмене raw/stderr. Два offline-пересчета в тесте
  дают прежние scorecards и сохраняют исходные файлы.

Пропущены: A05 saved-demo (1); Docker boundary с opt-in окружением (6);
multi-run SberLab (1); sandbox manager SberLab/AutoDealer (2);
sandbox manager с закрепленным образом (2); sandbox runner с образом (1);
sandbox session SberLab (3); Stage 1 E2E opt-in (1);
Stage 2 с отдельным operator checkout (1). Новые runtime/LLM-проверки не запускались.

## Реальный offline-пересчет

Пересчет выполнен на чистом закрепленном Juice Shop v20.2.0:
`5658473cf8814459bf89000ce373b20ed0b4eb37`, 1300 tracked-файлов.
Профиль: `93303d3677dcd41c773d7ddaa59e1215d1659bb8ab70d272ff454d06b24f4ae6`.

```bash
python -m scripts.b02_sast_development \
  --target artifacts/benchmark-target/juice-shop \
  --reuse-raw artifacts/b02-sast-development-2026-10-13-final \
  --output artifacts/b02-sast-rescore-new
```

Результат сохранен в `artifacts/b02-sast-rescore-2026-10-14/` с отдельным
`seal.json`. Три scorecard и шесть raw/stderr-файлов совпали с исходниками
побайтно. Исходный пакет B02 не изменен.

| SAST | Обнаружено уязвимых DEV-случаев | Recall обнаружения | Safe FP |
|---|---:|---:|---:|
| A06 before | 1/20 | 5% | 0/2 |
| B02 agent | 7/20 | 35% | 0/2 |
| B02 baseline | 7/20 | 35% | 0/2 |

Это результат статического обнаружения. Runtime-подтверждений здесь нет;
88 B02 alerts вне каталога остаются неклассифицированными. У сканера сохранена
61 диагностика неполного покрытия. HOLDOUT не оценивался.
