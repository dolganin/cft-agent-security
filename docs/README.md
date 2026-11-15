# Документация

Начните с [README проекта](../README.md). Здесь собраны действующие точки входа,
результаты и история разработки. Номера A/B/C и R обозначают этапы команды,
а не независимые продукты или гарантии готовности.

## Текущее состояние и результаты

| Документ | Назначение |
|---|---|
| [Метрики со scoring](bespalov-metrics-with-scoring-2026-10-16.md) | Последняя сводка одного прохода, знаменатели и ограничения |
| [Поиск и исправления](search-repair-integration-2026-10-16.md) | Запуск интегрированной версии и опубликованные архивы |
| [Аудит серьезности и CP](scoring-audit-2026-10-16.md) | Офлайн-расчет и статус модельного CP-черновика |
| [Полный research-проход](juice-full-research-report-2026-10-16.md) | Ход исследования и неподтвержденные случаи |
| [Первоначальная сводка](bespalov-metrics-2026-10-16.md) | История до дополнения scoring; не заменяет свежую сводку |

## Запуск и архитектура

- [CLI, подключение проекта и CI/CD](usage/cli-and-ci.md).
- [Контракты и границы безопасности](../AGENTS.md).
- [Правила разработки](../CONTRIBUTING.md).
- [Подготовка лаборатории](k01-environment-passport.md).
- [Демонстрационный сценарий](demo/README.md).
- [Локальный магазин для короткого показа](demo/order-store.md).
- [RepositoryScout](source-scout.md).
- [Исследовательский цикл](research-loop-r04.md).
- [Базовые исследовательские инструменты](research-foundation-report-2026-10-15.md).
- [Интеграция исследования и проверки](research-integration-r05-r07.md).
- [Восстановление после сбоев и браузер](research-r07-recovery-r08-browser.md).
- [Приватные тестовые роли](research-private-fixture-campaign-2026-10-15.md).

## Эталон и измерения: этап A

Исторические протоколы и результаты сохраняются неизменными. Нельзя смешивать
разные версии правил, роли и бюджеты в одно строгое сравнение.

| Этап | Документ |
|---|---|
| A01 | [Протокол измерений](a01-measurement-protocol.md) |
| A02 | [Каталог уязвимостей](a02-positive-vulnerability-catalog.md) |
| A03 | [Безопасные контроли и reset](a03-safe-controls-and-reset.md), [расширение](a03-1-negative-control-expansion.md) |
| A04 | [Заморозка эталона](a04-benchmark-freeze.md) |
| A05 | [Оценщик benchmark v2](a05-benchmark-v2.md) |
| A06 | [SAST/DAST baseline](a06-scanner-baselines.md), [серия](a06-baseline-series.md), [метрики](a06-metrics-2026-10-13.md) |
| A07 | [Исходная серия агента](a07-baseline-series.md), [интеграционная проверка](a07-integration-review.md) |
| A08 | [Результаты](a08-results-2026-10-13.md), [пакет](a08-published-artifacts.md), [дополнение](a08-supplement-2026-10-14.md), [приложение](a08-technical-appendix-2026-10-13.md) |

Исходники эталона: [benchmarks/](../benchmarks/).
Переход между этапами: [история benchmark и этап B](benchmark-history-and-stage-b.md).

## Поиск и доказательная проверка: этап B

| Этап | Документ |
|---|---|
| B01 | [Привязка source, handler и endpoint](b01-reliable-verification-binding.md) |
| B02 | [SAST](b02-sast.md), [интеграция](b02-integration-2026-10-14.md) |
| B03 | [Исследование исходников](b03-source-exploration.md), [приемка](b03-acceptance-2026-10-14.md) |
| B04 | [Роли и контрольные случаи](b04-access-fixtures.md) |
| B05 | [Проверка контроля доступа](b05-access-control-verification.md) |
| B06 | [Runtime-проверки](b06-runtime-report-2026-10-14.md), [спецификация](b06-verification-specification.md) |
| B07 | [Восстановление workflow](b07-workflow-recovery.md) |
| B08 | [Оценка серьезности и CP](b08-scoring-progress.md) |
| B09 | [Один измеренный проход](b09-single-run-report-2026-10-15.md) |

## Исправления: этап C

Поддерживаются два семейства: SQL-поиск и redirect allowlist. Исправленный патч
должен пройти независимую проверку, а не только получить одобрение модели.

| Этап | Документ |
|---|---|
| C01 | [Область допустимых исправлений](c01-fix-scope.md) |
| C02 | [Генерация патчей](c02-llm-patch-proposals.md) |
| C03 | [Независимая BEFORE/AFTER-проверка](c03-independent-patch-verification.md) |
| C04 | [Ограниченный цикл исправления](c04-bounded-repair-loop.md) |
| C05 | [Протокол измерения](c05-repair-measurement.md), [историческая сводка](evidence/c05/report.md) |

## Целевые проверки Juice Shop

- [Source-detectors](juice-source-detectors.md).
- [Бюджет fixture-проверок](juice-fixture-budget-integration-2026-10-16.md).
- [Отзывы и NoSQL](juice-review-verification-report-2026-10-16.md).
- [Атрибуция feedback](juice-feedback-owner-report-2026-10-16.md).
- [Приемка доступных протоколов](juice-all-ready-verification-report-2026-10-16.md).
- [Минимальные proof-сценарии](juice-incremental-mini-proofs.md).
- [Диагностические исправления](research-r09-diagnostic-repairs.md).
- [Сохранение прерванных запусков](research-run-recovery-2026-10-15.md).

## Доказательства и воспроизведение

- [Архивы передач](../artifacts/handoffs/) — пакеты с SHA256 и manifest.
- [C03](evidence/c03/README.md), [C04](evidence/c04/README.md), [C05](evidence/c05/README.md) — состав и ограничения данных.
- [Scoring audit](evidence/scoring-audit-2026-10-16/) — производные расчеты серьезности.
- [Public-commerce CP](evidence/public-commerce-cp-2026-10-16/) — сценарий и модельный черновик, не утвержденный человеком эталон.

## Планы и история

Эти документы отражают решения на дату создания, не текущие гарантии реализации.
Актуальное поведение проверяйте по коду, тестам и соответствующей приемке.

- [Три этапа MVP: A/B/C](mvp-three-stage-plan-2026-10-11.md).
- [Специализация под Juice Shop](juice-shop-metrics-maximization-plan-2026-10-15.md).
- [План исследовательского агента](research-agent-development-plan-2026-10-15.md).
- [Неподтвержденные случаи](juice-verification-gap-plan-2026-10-15.md).
- [Инкрементальные улучшения](juice-incremental-agent-improvement-plan-2026-10-16.md).
- [Первоначальный план](agent-completion-plan-2026-10-10.md), [исторические задачи](agent-team-tasks-2026-10-10.md).

Остальные датированные отчеты и промежуточные проекты протоколов остаются по своим
прежним адресам для трассировки решений. Их наличие не означает, что описанная
экспериментальная возможность включена в основной pipeline.
