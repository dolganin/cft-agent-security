"""Run the bundled chat demo without the API or browser, through the same pipeline."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

from app.config import settings
from app.demo import ORDER_PROFILE, ORDER_TEMPLATE, ROOT, run_demo_pipeline
from app.setup import SetupError, configured_demo_routes, require_model_credentials


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-mode", choices=("llm", "stub"), default="llm",
                        help="llm: real model; stub: registered checks without LLM reasoning")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/demo-cli"),
                        help="New or empty output directory; previous evidence is never overwritten")
    args = parser.parse_args(argv)
    if Path.cwd().resolve() != ROOT:
        parser.error(f"Запустите команду из корня репозитория: {ROOT}")
    destination = args.output_dir.expanduser().resolve()
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        parser.error("Каталог результатов уже содержит данные. Выберите новый --output-dir.")
    if args.agent_mode == "llm":
        try:
            require_model_credentials(settings)
        except (SetupError, ValueError) as exc:
            parser.error(str(exc))
    print("Режим: живая модель" if args.agent_mode == "llm" else
          "Режим: stub — проверка CI-интеграции без модели; качество поиска не измеряется.")
    previous_routes = settings.llm_routes
    try:
        settings.llm_routes = configured_demo_routes(settings)
        with tempfile.TemporaryDirectory(prefix="cft-demo-cli-") as temporary:
            target = Path(temporary) / "order-store"
            shutil.copytree(ORDER_TEMPLATE, target)
            code = run_demo_pipeline(argparse.Namespace(
                target=str(target), target_repository=None, profile=str(ORDER_PROFILE),
                architecture=None, architecture_overrides=None, findings=None,
                sast_config=str(ROOT / "docs/demo/order-store-semgrep.yaml"),
                output_dir=str(destination), agent_mode=args.agent_mode,
                max_iterations=1, full_reports=False, base_ref=None, head_ref="HEAD",
                base_findings=None, base_architecture=None,
            ))
        gate_path = destination / "gate.json"
        if gate_path.is_file():
            gate = json.loads(gate_path.read_text(encoding="utf-8"))
            print(f"\nРезультат: {gate['decision']}; код завершения: {code}.")
            print(f"Подтверждено: {gate['confirmed']}; недостаточно данных: {gate['inconclusive']}.")
        print(f"Отчеты и доказательства: {destination}")
        return code
    finally:
        settings.llm_routes = previous_routes


if __name__ == "__main__":
    sys.exit(main())
