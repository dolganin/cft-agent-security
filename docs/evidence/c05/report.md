# C05 — измерения исправлений

Protocol SHA256: `00841636e4afa6cfa7076759c58c1500b104816e0cac0be1dd2d97fc926c8939`.

Eligible / confirmed: **2/5** unique benchmark cases.
Verified / eligible: **6/6** case-runs.
Попыток: 6; REGRESSION attempts: 0.
Статусы: `{"FIXED": 6, "INTERRUPTED": 0, "NOT_FIXED": 0, "NOT_RUN": 0, "TECHNICAL_ERROR": 0}`.

| Слот | Результат | Попытки | Регрессии | Весь слот, с | До verified patch, с | Причина |
|---|---|---:|---:|---:|---:|---|
| 01-sql-search | FIXED | 1 | 0 | 165.758 | 165.758 | independently_verified |
| 01-redirect-allowlist | FIXED | 1 | 0 | 302.837 | 302.837 | independently_verified |
| 02-sql-search | FIXED | 1 | 0 | 166.366 | 166.366 | independently_verified |
| 02-redirect-allowlist | FIXED | 1 | 0 | 288.335 | 288.335 | independently_verified |
| 03-sql-search | FIXED | 1 | 0 | 173.555 | 173.555 | independently_verified |
| 03-redirect-allowlist | FIXED | 1 | 0 | 302.786 | 302.786 | independently_verified |

## Время

- Confirmed-input → independently verified patch: n=6; mean 233.273 s; median 230.945 s; min–max 165.758–302.837 s.
- Fresh BEFORE confirmed → independently verified patch: n=6; mean 112.689 s; median 114.663 s; min–max 75.596–147.599 s.

Неуспехи не входят в среднее времени успешного исправления, но остаются в таблице и знаменателе.
Historical/production MTTR: **N/A**. Календарное время от B09 включает простой; оно сохранено отдельно в JSON.

## Воспроизведение и границы

Исходный B09 SHA256: `6ba2f4d4fcc23871f96f1bb141eb62bfae5b792904252cdb2ff2c28980a2d5c7`; полный архив — `b09-full-search.zip`.
Модель: `nsu:qwen3.8-flash-next`; лимиты: `{"max_attempts": 3, "wall_clock_seconds": 900.0}`.
Команда: `python -m app.repair_measurement --replay --output <extracted-series>`.
Это проекция полного sealed пакета. Она не заменяет raw C04/C03 receipts и source snapshots.
Known DEV corpus; две выбранные причины, три повтора. Проценты описательные, не оценка всех классов.
Полный B09 сохранён отдельно от fix-среза. C05 не повышает исторические search/confirmation Recall.
