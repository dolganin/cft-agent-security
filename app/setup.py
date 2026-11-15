"""Explicit first-run checks and provisioning for the bundled local demo."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO_ROUTES = "nsu:Qwen3.8-27B"
WORKER_IMAGE = "python:3.12-alpine"
DIGEST_IMAGE = re.compile(r"^[^\s]+@sha256:[0-9a-f]{64}$")


class SetupError(RuntimeError):
    pass


def command(argv, *, timeout=30, output=False):
    from app.ci_pipeline import target_subprocess_environment

    try:
        result = subprocess.run(argv, cwd=ROOT, env=target_subprocess_environment(),
                                text=True, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError:
        raise SetupError(f"Не найдена команда {argv[0]}. Установите её и откройте новый терминал.") from None
    except subprocess.TimeoutExpired:
        raise SetupError(f"Команда {argv[0]} не завершилась за {timeout} с.") from None
    if result.returncode:
        hint = " Проверьте, что Docker Desktop запущен." if argv[0] == "docker" else ""
        raise SetupError(f"Не выполнена команда {' '.join(argv[:4])}.{hint}")
    if output:
        print(result.stdout.strip())
    return result.stdout.strip()


def check_tools():
    version = command(["node", "--version"]).lstrip("v")
    parts = tuple(int(p) for p in version.split(".")[:2])
    if not (parts[0] == 20 and parts[1] >= 19 or parts >= (22, 12)):
        raise SetupError("Для интерфейса нужен Node.js 22.12+ (или 20.19.x).")
    command(["npm", "--version"])
    semgrep = Path(sys.executable).parent / ("semgrep.exe" if os.name == "nt" else "semgrep")
    if not semgrep.is_file():
        found = shutil.which("semgrep")
        if not found:
            raise SetupError('Установите сканер: python -m pip install -c requirements-first-run.txt -e ".[dev,sast]"')
        semgrep = Path(found)
    command([str(semgrep), "--version"], timeout=60)
    command(["docker", "version", "--format", "{{.Server.Version}}"])
    command(["docker", "compose", "version", "--short"])
    print("Python, Node.js, npm, Semgrep, Docker и Compose доступны.")


def env_image(path: Path, image: str):
    """Change only the image setting, preserving all existing credentials/text."""
    if not DIGEST_IMAGE.fullmatch(image):
        raise SetupError("Образ проверок должен быть закреплён по SHA-256.")
    content = path.read_text(encoding="utf-8") if path.exists() else (ROOT / ".env.example").read_text(encoding="utf-8")
    line = "CFT_SANDBOX_IMAGE=" + image
    updated, count = re.subn(r"^\s*CFT_SANDBOX_IMAGE\s*=.*$", lambda _: line,
                            content, flags=re.MULTILINE)
    if not count:
        updated = content.rstrip() + "\n" + line + "\n"
    path.write_text(updated, encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def configured_demo_routes(config) -> str:
    """Respect the operator's provider selection; retain the tested default."""
    return config.llm_routes.strip() or DEMO_ROUTES


def require_model_credentials(config):
    from agent.llm import parse_route_specs

    routes = parse_route_specs(configured_demo_routes(config))
    credentials = config.llm_provider_credentials()
    for route in routes:
        if credentials.get(route.key_env) and (
            route.provider != "cloudflare" or credentials.get("CLOUDFLARE_ACCOUNT_ID")
        ):
            return routes
    required = list(dict.fromkeys(route.key_env for route in routes))
    if any(route.provider == "cloudflare" for route in routes):
        required.append("CLOUDFLARE_ACCOUNT_ID")
    raise SetupError("Укажите в .env учетные данные выбранного провайдера: " + ", ".join(required))


def check_model(config):
    from agent.llm import LLMUnavailableError, ProviderFailoverClient
    from schemas.llm import LLMProbeResult

    client = ProviderFailoverClient(routes=require_model_credentials(config),
        credentials=config.llm_provider_credentials(), timeout_seconds=20,
        max_output_tokens=256, reasoning_effort="low")
    try:
        client.complete_model(output_model=LLMProbeResult,
            system_prompt="Connectivity check. Return only the requested JSON object; do not call tools.",
            user_payload={"task": "Return status=ready and note=connection works."}, operation="setup_probe")
    except (LLMUnavailableError, ValueError):
        raise SetupError("Модель не ответила: проверьте ключ, CFT_LLM_ROUTES и доступ к провайдеру.") from None
    print("Подключение к выбранной модели проверено.")


def check_demo(*, config, port=8080, preview_port=8090, probe_model=False):
    if not (1 <= port <= 65535 and 1 <= preview_port <= 65535) or port == preview_port:
        raise SetupError("Укажите два разных порта от 1 до 65535 для API и магазина.")
    check_tools()
    image = config.sandbox_image
    if not DIGEST_IMAGE.fullmatch(image):
        raise SetupError("Не подготовлен образ проверок. Выполните: python -m app.setup --prepare-demo")
    command(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    if not (ROOT / "frontend/node_modules/vite").is_dir():
        raise SetupError("Не установлены зависимости интерфейса. Выполните npm ci в каталоге frontend.")
    for selected in (port, preview_port):
        try:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", selected))
        except OSError:
            raise SetupError(f"Порт {selected} занят. Остановите предыдущий сервер или выберите другой порт.") from None
    if probe_model:
        check_model(config)
    else:
        require_model_credentials(config)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-demo", action="store_true", help="Явно загрузить и подготовить Docker-образы")
    parser.add_argument("--check-model", action="store_true", help="Проверить ключ реальным коротким запросом")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--preview-port", type=int, default=8090)
    args = parser.parse_args()
    if Path.cwd().resolve() != ROOT:
        print(f"Перейдите в каталог репозитория: {ROOT}", file=sys.stderr)
        return 2
    try:
        from app.config import Settings

        config = Settings()
        if args.prepare_demo:
            check_tools()
            check_model(config)
            print("Загружаем образ проверок. На первом запуске это может занять несколько минут.")
            command(["docker", "pull", WORKER_IMAGE], timeout=600)
            digests = json.loads(command(["docker", "image", "inspect", WORKER_IMAGE,
                                         "--format", "{{json .RepoDigests}}"]))
            if not digests or not DIGEST_IMAGE.fullmatch(digests[0]):
                raise SetupError("Docker не вернул неизменяемый digest образа проверок.")
            env_image(ROOT / ".env", digests[0])
            print("Образ проверок закреплён в .env по SHA-256. Собираем локальный магазин.")
            command(["docker", "compose", "--file", str(ROOT / "demo-target/order-store/compose.yaml"),
                     "build"], timeout=600)
            config = Settings()
        check_demo(config=config, port=args.port, preview_port=args.preview_port,
                   probe_model=args.check_model and not args.prepare_demo)
        print("Готово. Запустите python -m app.demo, затем npm run dev в каталоге frontend.")
        return 0
    except (SetupError, OSError, ValueError) as exc:
        print(f"Подготовка не завершена: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
