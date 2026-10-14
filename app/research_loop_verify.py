"""Fixed developer checks and portable R04 logs; no model-supplied host commands."""
import argparse
import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path


def run(output, image):
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError("Choose a fresh verification directory")
    output.mkdir(parents=True)
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    env.pop("CFT_RESEARCH_IMAGE", None)
    checks = {}
    commands = {
        "unit-suite": [sys.executable, "-m", "pytest", "-q", "-rs", "--disable-warnings"],
        "ruff": [sys.executable, "-m", "ruff", "check", "."],
        "legacy-graph": [sys.executable, "-m", "app.main"],
        "docker-loop-test": [sys.executable, "-m", "pytest", "-q", "tests/test_research_agent.py", "--disable-warnings"],
        "diff-check": ["git", "diff", "--check"],
    }
    for name, command in commands.items():
        result = subprocess.run(command, text=True, capture_output=True, check=False, timeout=180,
                                env={**env, **({"CFT_RESEARCH_IMAGE": image} if name == "docker-loop-test" else {})})
        (output / (name + ".log")).write_text(result.stdout + result.stderr)
        checks[name] = {"exit_code": result.returncode, "passed": result.returncode == 0}
        print(json.dumps({"check": name, **checks[name]}), flush=True)
    summary = {"checks": checks, "passed": all(x["passed"] for x in checks.values()),
               "benchmark_measurement": False, "live_llm": False}
    (output / "verification.json").write_text(json.dumps(summary, indent=2) + "\n")
    seal = {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.rglob("*")) if p.is_file()}
    (output / "seal.json").write_text(json.dumps(seal, indent=2) + "\n")
    if not summary["passed"]:
        raise RuntimeError("R04 verification failed; logs retained")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    run(args.output, args.image)
