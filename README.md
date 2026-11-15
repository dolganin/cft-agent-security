<div align="center">

# CFT Security Agent

**ИИ-агент для анализа безопасности кода и проверки уязвимостей в CI/CD.**

[![Быстрый запуск](https://img.shields.io/badge/%D0%91%D1%8B%D1%81%D1%82%D1%80%D1%8B%D0%B9_%D0%B7%D0%B0%D0%BF%D1%83%D1%81%D0%BA-2563eb?style=for-the-badge)](#быстрый-запуск) [![Чат](https://img.shields.io/badge/%D0%A7%D0%B0%D1%82-334155?style=for-the-badge)](#работа-с-проектом) [![CLI](https://img.shields.io/badge/CLI-334155?style=for-the-badge)](#cli) [![CI/CD](https://img.shields.io/badge/CI%2FCD-334155?style=for-the-badge)](#cicd) [![Документация](https://img.shields.io/badge/%D0%94%D0%BE%D0%BA%D1%83%D0%BC%D0%B5%D0%BD%D1%82%D0%B0%D1%86%D0%B8%D1%8F-334155?style=for-the-badge)](docs/README.md)

</div>

![Интерфейс агента](docs/images/chat-workspace.png)

| Возможность | Что делает агент |
|---|---|
| Поиск | Анализирует исходники с помощью Semgrep и языковой модели |
| Проверка | Выполняет разрешенные проверки в Docker и собирает доказательства |
| Отчет | Показывает файлы, строки, команды, серьезность и контекстный приоритет |
| Интеграция | Работает через чат, CLI и CI/CD; сохраняет отчеты в JSON |

## Быстрый запуск

**Требования:** Python 3.11+ (зависимости проверены на 3.11) · Node.js 22.12+ · Docker с Compose v2 · API-ключ LLM-провайдера.

### 1. Установка

<details open>
<summary><b>macOS / Linux / WSL2</b></summary>

```bash
git clone https://github.com/Ultramind-AI/cft-security-agent.git
cd cft-security-agent
python3 -m venv .venv
source .venv/bin/activate
pip install -c requirements-first-run.txt -e ".[dev,sast]"
npm --prefix frontend ci
cp .env.example .env
```

</details>

<details>
<summary><b>Windows: подготовка WSL2</b></summary>

Установите Ubuntu из PowerShell.

```powershell
wsl --install -d Ubuntu
```

Если установка сама открыла Ubuntu и появилось приглашение `user@...$`, переходите к командам `apt` ниже. Чтобы открыть уже установленную Ubuntu позже, выполните в PowerShell:

```powershell
wsl -d Ubuntu
```

В Ubuntu установите системный Python и поддержку виртуальных окружений.

```bash
sudo apt update
sudo apt install python3 python3-venv
```

Перед клонированием перейдите в домашнюю папку Ubuntu.

```bash
cd ~
```

В Docker Desktop включите **Settings → Resources → WSL Integration**.
Установите Node.js 22.12+ внутри Ubuntu, затем выполните команды Linux выше. Если вы уже в папке проекта, пропустите `git clone` и `cd cft-security-agent`.

</details>

### 2. Модель

Укажите провайдера, модель и ключ в `.env`. Пример для NSU:

```dotenv
NSU_OPENWEBUI_KEY=ваш-ключ
CFT_LLM_ROUTES=nsu:Qwen3.8-27B
```

Также поддерживаются **Groq, Mistral, Gemini, OpenRouter, NVIDIA NIM, Z.ai и Cloudflare**.
[Переменные и примеры настройки →](docs/usage/cli-and-ci.md#настройка-модели)

### 3. Docker

Запустите Docker и подготовьте окружение:

```bash
python -m app.setup --prepare-demo
```

<details>
<summary><b>Команды Docker для ручной подготовки</b></summary>

```bash
docker pull python:3.12-alpine
docker image inspect python:3.12-alpine --format '{{index .RepoDigests 0}}'
docker compose -f demo-target/order-store/compose.yaml build
```

Запишите полученный digest в `.env` как `CFT_SANDBOX_IMAGE`.

</details>

### 4. Запуск

**API** — в терминале с активной `.venv`:

```bash
python -m app.demo
```

**Интерфейс** — во втором терминале из корня проекта:

```bash
npm --prefix frontend run dev -- --strictPort
```

**[Открыть интерфейс → http://localhost:5173](http://localhost:5173)** · [API: http://localhost:8080/docs](http://localhost:8080/docs)

Остановка — **Ctrl+C** в обоих терминалах. [Другие порты и диагностика →](docs/usage/cli-and-ci.md#другие-порты)

## Работа с проектом

**Открыть проект → выбрать папку или ZIP → отправить запрос в чат.**

Например: `Проведи полный анализ безопасности проекта`.
В блоке **«Ход проверки»** видны команды и доказательства; в полном отчете —
находки с файлами и строками. После анализа можно задавать уточняющие вопросы.
Для первого знакомства доступен встроенный пример в разделе **«Проекты»**.

## CLI

Проверка встроенного примера без запуска интерфейса:

```bash
python -m app.demo_check --output-dir artifacts/demo-cli
```

Для своего проекта используйте **`cft-security-ci`** — полный pipeline с Docker,
или **`cft-security-pipeline`** — анализ без управления запуском приложения.
[Параметры и команды →](docs/usage/cli-and-ci.md#общие-cli-команды)

## CI/CD

[GitHub Actions workflow](.github/workflows/quickstart-check.yml) запускает тесты,
собирает интерфейс и проверяет Docker/SAST-контур. Локальная проверка интеграции без LLM:

```bash
python -m app.demo_check --agent-mode stub --output-dir artifacts/ci-smoke
```

| Код завершения | Значение |
|:---:|---|
| **0** | `pass` или `warn`; подробности в `gate.json` |
| **1** | Подтвержденный риск блокирует сборку |
| **2** | Техническая ошибка выполнения |

[Подключение своего проекта к CI/CD →](docs/usage/cli-and-ci.md#подключение-к-cicd)

---

Проверочные протоколы зависят от профиля проекта. Подтвержденная находка требует
доказательств; неизвестный результат остается неопределенным.

[Архитектура](docs/diagrams/architecture.svg) · [Настройка и CLI](docs/usage/cli-and-ci.md) · [Документация](docs/README.md)
