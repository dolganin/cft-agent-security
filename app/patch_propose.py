"""Generate one real LLM patch proposal for a C01 family; never apply it."""
import argparse
import json
from pathlib import Path

from agent.llm import ProviderFailoverClient, parse_route_specs
from app.config import Settings
from fix_verification.generation import generate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--family", choices=("sql-search", "redirect-allowlist"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--route", default="nsu:qwen3.8-flash-next")
    args = parser.parse_args()
    routes = parse_route_specs(args.route, allow_external_fallbacks=False)
    if len(routes) != 1:
        parser.error("C02 allows exactly one operator-selected provider route")
    client = ProviderFailoverClient(routes=routes, credentials=Settings().llm_provider_credentials(),
        timeout_seconds=45, max_output_tokens=3072, reasoning_effort="low", trace=False)
    artifact = generate(repository=args.target, family=args.family, output=args.output, client=client)
    print(json.dumps({"status": artifact.status, "reason": artifact.reason,
                      "provider": artifact.provider_route, "applied": False}))
    return 0 if artifact.status == "ready_for_review" else 2


if __name__ == "__main__":
    raise SystemExit(main())
