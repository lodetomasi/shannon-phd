"""Single-experiment CLI: run Auriga end-to-end against one target.

Usage:
    python -m experiments.run_experiment \
        --target juice-shop \
        --repo data/_cache/targets/juice-shop \
        --model claude-sonnet-4-6 \
        --condition baseline \
        --out results/run-001.jsonl

To run an adversarial cell, pass --payload-id (the payload library
contains 24 entries — see paper/payloads/library/seed_payloads.json).
The runner copies the repo, applies the payload via paper/payloads/injector.py,
and then runs Auriga on the mutated copy. The original repo is never modified.

Real LLM only — no mock backend exists. Requires ANTHROPIC_API_KEY.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional

from agent.core.budget import Budget
from agent.llm.anthropic_client import AnthropicClient
from agent.llm.bedrock_client import BedrockAnthropicClient
from agent.llm.bedrock_converse_client import BedrockConverseClient
from agent.llm.interface import LLMClient
from agent.runner import Planner

from models.registry import load_catalog

from payloads.injector import inject
from payloads.taxonomy import load_library


def _resolve_payload(repo_root: Path, payload_id: str) -> Path:
    """Copy the repo to a temp dir, inject the payload, return the copy path."""
    library = load_library(
        Path(__file__).resolve().parents[1] / "payloads" / "library" / "seed_payloads.json"
    )
    matching = [p for p in library if p.payload_id == payload_id]
    if not matching:
        raise SystemExit(f"unknown payload id: {payload_id}")
    payload = matching[0]
    tmp = Path(tempfile.mkdtemp(prefix="auriga-injected-"))
    target = tmp / repo_root.name
    shutil.copytree(repo_root, target)
    result = inject(target, payload)
    print(f"applied payload {payload_id} -> {result.file_path} (+{result.bytes_added} bytes)",
          file=sys.stderr)
    return target


# Bedrock model ids that need the Converse client (non-Anthropic) and
# their tool-use / system-prompt capabilities. Models not listed default
# to the Anthropic-on-Bedrock InvokeModel client.
_CONVERSE_MODEL_FLAGS: dict[str, dict[str, bool]] = {
    "mistral.mistral-7b-instruct-v0:2": {"tool_use": False, "system": False},
    "mistral.mistral-large-2402-v1:0": {"tool_use": True, "system": True},
    "mistral.mixtral-8x7b-instruct-v0:1": {"tool_use": False, "system": True},
    "openai.gpt-oss-20b-1:0": {"tool_use": False, "system": True},
    "openai.gpt-oss-120b-1:0": {"tool_use": False, "system": True},
    "qwen.qwen3-32b-v1:0": {"tool_use": False, "system": True},
    "google.gemma-3-12b-it": {"tool_use": False, "system": True},
}


def _build_llm(model_id: str, aws_region: str = "eu-west-1") -> LLMClient:
    catalog = load_catalog()
    model = catalog.by_id(model_id)
    if model.provider == "anthropic":
        return AnthropicClient(
            model=model.id,
            input_price_per_mtok=model.input_price_per_mtok,
            output_price_per_mtok=model.output_price_per_mtok,
        )
    if model.provider == "aws-bedrock":
        if model.id.startswith("anthropic."):
            return BedrockAnthropicClient(
                model_id=model.id,
                region=aws_region,
                input_price_per_mtok=model.input_price_per_mtok,
                output_price_per_mtok=model.output_price_per_mtok,
            )
        flags = _CONVERSE_MODEL_FLAGS.get(model.id, {"tool_use": True, "system": True})
        return BedrockConverseClient(
            model_id=model.id,
            region=aws_region,
            input_price_per_mtok=model.input_price_per_mtok,
            output_price_per_mtok=model.output_price_per_mtok,
            supports_tool_use=flags["tool_use"],
            supports_system_prompt=flags["system"],
        )
    raise SystemExit(
        f"model {model_id!r} provider {model.provider!r} is not wired in the CLI yet"
    )


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Run one Auriga experiment end-to-end.")
    p.add_argument("--target", required=True, help="In-scope target host, e.g. 'juice-shop'")
    p.add_argument("--repo", required=True, help="Path to target source repository")
    p.add_argument("--model", required=True, help="Model id from models/catalog.json")
    p.add_argument("--condition", default="baseline")
    p.add_argument("--payload-id", default=None,
                   help="If set, applies the payload to a copy of --repo before running")
    p.add_argument("--out", required=True, help="JSONL output path")
    p.add_argument("--max-usd", type=float, default=10.0)
    p.add_argument("--max-walltime-seconds", type=float, default=1800.0)
    p.add_argument("--max-llm-calls", type=int, default=200)
    p.add_argument("--task", default="Find and validate exploitable vulnerabilities.")
    p.add_argument("--aws-region", default=os.environ.get("AWS_REGION", "eu-west-1"))
    args = p.parse_args(argv)

    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        raise SystemExit(f"repo path not a directory: {repo}")

    if args.payload_id:
        repo = _resolve_payload(repo, args.payload_id)

    llm = _build_llm(args.model, aws_region=args.aws_region)
    budget = Budget(
        max_usd=args.max_usd,
        max_walltime_seconds=args.max_walltime_seconds,
        max_llm_calls=args.max_llm_calls,
    )
    planner = Planner(
        llm=llm,
        target_host=args.target,
        repo_root=repo,
        budget=budget,
        condition=args.condition,
        payload_id=args.payload_id,
        out_jsonl=Path(args.out),
    )
    outcome = planner.run(args.task)
    summary = {
        "run_id": outcome.record.run_id,
        "target": outcome.record.target,
        "condition": outcome.record.condition,
        "payload_id": outcome.record.payload_id,
        "confirmed_findings": len(outcome.confirmed_findings),
        "stages": [
            {"name": s.name, "stop_reason": s.stop_reason, "steps": s.steps}
            for s in outcome.stages
        ],
        "budget": outcome.record.tokens_in,
        "walltime_seconds": outcome.record.walltime_seconds,
    }
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
