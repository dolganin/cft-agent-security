# CLI и CI/CD

Команды выполняются из корня репозитория с активной `.venv` после установки
зависимостей по [README](../../README.md#быстрый-запуск).

## Настройка модели

В `.env` задайте ключ провайдера и `CFT_LLM_ROUTES` в формате `провайдер:модель`.
API, CLI и подготовка окружения используют эту настройку. Пустой маршрут в
быстром запуске означает `nsu:Qwen3.8-27B`.

| Провайдер | Ключ | Формат маршрута |
|---|---|---|
| NSU | `NSU_OPENWEBUI_KEY` | `nsu:MODEL_ID` |
| Groq | `GROQ_API_KEY` | `groq:MODEL_ID` |
| Mistral | `MISTRAL_API_KEY` | `mistral:MODEL_ID` |
| Gemini | `GEMINI_API_KEY` | `gemini:MODEL_ID` |
| OpenRouter | `OPENROUTER_API_KEY` | `openrouter:MODEL_ID` |
| NVIDIA NIM | `NVIDIA_NIM_API_KEY` | `nvidia:MODEL_ID` |
| Z.ai | `ZAI_API_KEY` | `zai:MODEL_ID` |
| Cloudflare | `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID` | `cloudflare:MODEL_ID` |

`MODEL_ID` замените идентификатором модели из своего аккаунта провайдера.
Несколько маршрутов через запятую образуют последовательность переключения
при ошибках. Пример с проверенной в проекте моделью NSU:

```dotenv
NSU_OPENWEBUI_KEY=ваш-ключ
CFT_LLM_ROUTES=nsu:Qwen3.8-27B
```

Для другого провайдера укажите его ключ и маршрут вместо этих двух строк.
Ключи не передаются контейнеру анализируемого приложения.

## Быстрый CLI с живой моделью

```bash
python -m app.demo_check --output-dir artifacts/demo-cli
python -m json.tool artifacts/demo-cli/gate.json
```

Сервер API, Vite и браузер не нужны. Команда создает временную копию учебного
магазина и вызывает тот же `app.demo.run_demo_pipeline`, что чат. Он использует
канонический `app.ci_pipeline`: Discovery → Docker → Semgrep → модель → Validator
→ Executor → Evidence → отчеты → Gate. Профиль, правила, бюджет и модель
из `CFT_LLM_ROUTES` совпадают с быстрым сценарием UI. Шаблон магазина не меняется;
Docker-среда и временная копия удаляются после выполнения.

Результаты сохраняются независимо от процесса. Новый запуск требует нового
`--output-dir`. Код `1` означает блокирующий риск, `2` — техническую ошибку;
они намеренно передаются вызывающему shell/CI без замены на `0`.

## Общие CLI-команды

| Команда | Назначение |
|---|---|
| `python -m app.demo_check --help` | Короткий CLI встроенного магазина |
| `cft-security-ci --help` | Полный pipeline с запуском и остановкой Docker-среды |
| `cft-security-pipeline --help` | SAST, агент, отчеты и Gate без управления средой приложения |
| `cft-security-api` | Сервер API для зарегистрированных оператором проектов |

`cft-security-api` запускает API, а не первый демонстрационный сценарий. Его
настройки задаются переменными `CFT_API_*` из `.env.example`; `--help` у этого
entrypoint не является интерфейсом argparse. Для проверки API откройте `/docs`
работающего сервера. Для первого знакомства используйте `python -m app.demo`.

После активации `.venv` установленные `cft-security-*` находятся в PATH.
Эквиваленты первых двух общих команд: `python -m app.ci_pipeline` и
`python -m app.pipeline_run`.

### Проверка общего CI entrypoint на встроенном проекте

```bash
CFT_POLICY_FILE=policies/demo-order-store.yaml cft-security-ci \
  --target demo-target/order-store \
  --profile targets/demo-order-store.yaml \
  --sast-config docs/demo/order-store-semgrep.yaml \
  --agent-mode stub \
  --output-dir artifacts/ci-standard
```

Это реальный Docker/Semgrep-проход без LLM: ожидается `warn`, четыре
подтверждения, ноль технических ошибок и код `0`. Зарегистрированные
детерминированные протоколы получают настоящие Evidence и сохраняют audit;
режим не требует API-ключа и не измеряет качество reasoning модели.
Для живого быстрого анализа этого магазина используйте `app.demo_check`:
он также подключает операторскую политику и параметры компактного reasoning.

### Pipeline без запуска приложения

```bash
CFT_POLICY_FILE=policies/demo-order-store.yaml cft-security-pipeline \
  --target demo-target/order-store \
  --profile targets/demo-order-store.yaml \
  --sast-config docs/demo/order-store-semgrep.yaml \
  --agent-mode stub \
  --output-dir artifacts/source-standard
```

Команда выполняет статическую часть и workflow, но не создает управляемую
Docker-среду приложения. Без runtime-контекста нельзя ожидать подтверждения
динамических SQL/IDOR-сценариев. Это другой режим, а не быстрый аналог полного анализа.

## Свой проект

Через чат: «Открыть проект» → папка или ZIP → запрос на анализ.
Автоматическое определение структуры помогает запустить приложение, но не
гарантирует понимание любых внешних зависимостей или подтверждение всех типов ошибок.

Для предсказуемого CLI/CI запуска оператор готовит YAML `TargetProfile` в
`targets/`:

1. Указывает среду `sandbox`/`local`/`staging`, сервисы и архитектурный контекст.
2. Выбирает конкретный Compose-файл, внутренние порты и healthcheck.
3. Подключает правила SAST и допустимые проверочные протоколы.
4. Для удаленного CI задает `metadata.ci.repository` с разрешенным `owner/name`.
5. Проверяет профиль локально через `cft-security-ci` и изучает `gate.json`.

`targets/demo-order-store.yaml` — пример структуры, а не универсальная политика
для копирования на любой проект. CLI принимает доверенный профиль оператора;
модель не получает права добавлять адреса, пути и команды за пределами него.

Опции PR-анализа: `--base-ref`, `--head-ref`, `--base-findings` и
`--base-architecture`. Они сравнивают ревизии/результаты и показывают связь
находок с изменениями. Их описание есть в `cft-security-ci --help`.
Нужна Git-история и результаты соответствующей базовой ревизии; один параметр
`--base-ref` не создает корректный baseline автоматически.

## Подключение к CI/CD

Есть два workflow с разным назначением:

| Workflow | Что проверяет | Что нужно |
|---|---|---|
| [Quickstart check](../../.github/workflows/quickstart-check.yml) | Установку, Python/UI тесты, сборку и Docker/Semgrep smoke | Только этот репозиторий; без NSU-ключа |
| [CFT Security Pipeline](../../.github/workflows/security-pipeline.yml) | Качество кода, границы sandbox и Gate выбранного разрешенного проекта | Профиль, доступ к выбранному проекту, SberLab/AutoDealer для исторических boundary-тестов |

### Проверить CI локально

```bash
python -m app.demo_check --agent-mode stub --output-dir artifacts/ci-smoke
python -m json.tool artifacts/ci-smoke/gate.json
```

Проверяйте три вещи: `ci-summary.json` содержит `status: completed`,
в `gate.json` нет технических ошибок, а `warn` объяснен недостаточными
найденными неблокирующими проблемами магазина. Зеленый smoke означает успешное
выполнение проверки, а не отсутствие уязвимостей.

### Проверить на GitHub

Откройте репозиторий → **Actions → Quickstart check → Run workflow** → выберите
ветку → **Run workflow**. По завершении скачайте **Artifacts → quickstart-ci-smoke**.
В архиве будут `gate.json`, отчеты, Evidence, audit и события реального CI-smoke.
Если кнопки нет, проверьте права на запуск Actions в репозитории.

Quickstart также запускается при изменениях соответствующих файлов в main/PR.
Он не выполняет живой LLM-анализ, не измеряет Recall и не применяет исправления.

### Анализ разрешенного проекта в существующем workflow

В **Actions → CFT Security Pipeline → Run workflow** заполните
`target_repository`, `target_ref`, `target_profile`, `agent_ref`, `agent_mode`.
Профиль выбирается из доверенной копии агента, а его `metadata.ci.repository`
должна совпасть с `target_repository`. Публичный fork не предоставляет доступ
к приватным SberLab/AutoDealer: этот workflow требует настройки владельцем.

Для NSU добавьте `NSU_OPENWEBUI_KEY` в **Settings → Secrets and variables
→ Actions**; ключ не хранится в YAML и не передается контейнеру приложения.
В reusable-вызове секрет передается явно под тем же именем. Для другого
провайдера передайте его ключ и `CFT_LLM_ROUTES` через `env` шага запуска CLI.
Режим `stub` не использует модель. Итоговые артефакты сохраняются шагом
`Upload security artifacts` даже при блокирующем решении Gate.

Другой CI запускает тот же `cft-security-ci`, сохраняет весь `--output-dir`
и возвращает исходный код процесса: `0` для pass/warn, `1` для блокирующего
риска, `2` для технического сбоя. Не подменяйте любой ненулевой код успехом.

## Другие порты

Если стандартные 8080/8090/5173 уже заняты, выберите отдельные порты **до подготовки**.
В первом терминале:

```bash
python -m app.setup --prepare-demo --port 8082 --preview-port 8091
python -m app.demo --port 8082 --preview-port 8091 --data-dir api_data/isolated-demo
```

Во втором терминале, в том же корне проекта:

```bash
printf 'CFT_UI_API_PROXY=http://127.0.0.1:8082\n' > frontend/.env.local
npm --prefix frontend run dev -- --port 5174 --strictPort
```

Откройте <http://127.0.0.1:5174>. `frontend/.env.local` — локальная настройка,
не API-ключ. Команда `printf` заменяет этот файл; при наличии других настроек
измените только строку `CFT_UI_API_PROXY` редактором.

Диагностика на тех же свободных портах, при остановленном сервере:

```bash
python -m app.setup --check-model --port 8082 --preview-port 8091
```
