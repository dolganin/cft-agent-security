"""Select operator-owned project presets without changing the canonical pipeline."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STORE_PROFILE = ROOT / "targets/demo-order-store.yaml"
STORE_TEMPLATE = ROOT / "demo-target/order-store"
STORE_ID = "demo-order-store"


def run_project_pipeline(args) -> int:
    # A generated upload profile cannot opt in by copying a target id or name.
    if Path(args.profile).resolve() == STORE_PROFILE:
        from app.demo import run_demo_pipeline

        return run_demo_pipeline(args)
    from app.ci_pipeline import run_ci_pipeline

    return run_ci_pipeline(args)
