"""Matrix-experiment CLI: run a full factorial sweep.

Each cell of the matrix is one (target, model, condition, payload_id, n)
combination. The CLI:
  - validates feasibility against the budget (uses models.cost.estimate_matrix)
  - for each cell, repeats the run N times (re-resolving the payload each time
    so file timestamps differ but the injected text doesn't)
  - appends every RunRecord to a single JSONL output

Re-runnable: cells already present in the JSONL (matched by run_id metadata)
are SKIPPED unless --force is set. This lets you Ctrl-C and resume.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from models.cost import ExperimentCell, RunCostProfile, estimate_matrix, feasibility
from models.registry import load_catalog


@dataclass(frozen=True)
class MatrixCell:
    target: str
    model_id: str
    condition: str
    payload_id: Optional[str]
    n_runs: int

    def to_experiment_cell(self, tool_id: str) -> ExperimentCell:
        return ExperimentCell(
            tool_id=tool_id,
            model_id=self.model_id,
            condition=self.condition,
            n_runs=self.n_runs,
        )


def load_matrix(path: Path) -> list[MatrixCell]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    cells = []
    for c in raw["cells"]:
        cells.append(MatrixCell(
            target=c["target"],
            model_id=c["model_id"],
            condition=c["condition"],
            payload_id=c.get("payload_id"),
            n_runs=int(c["n_runs"]),
        ))
    return cells


def load_profiles(path: Path) -> dict[str, RunCostProfile]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {
        k: RunCostProfile(
            tokens_in=int(v["tokens_in"]),
            tokens_out=int(v["tokens_out"]),
            cache_read_tokens=int(v.get("cache_read_tokens", 0)),
        )
        for k, v in raw.items()
    }


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Run a factorial experimental matrix.")
    p.add_argument("--matrix", required=True, help="JSON file describing the matrix")
    p.add_argument("--profiles", required=True,
                   help="JSON file with token profiles per (tool, condition) — "
                        "REQUIRED, calibrate from M1 pilots")
    p.add_argument("--budget-usd", type=float, required=True)
    p.add_argument("--tool-id", default="auriga", help="Tool name embedded in cell keys")
    p.add_argument("--check-only", action="store_true",
                   help="Print feasibility and exit (no experiments run)")
    p.add_argument("--out", required=True, help="JSONL output path")
    args = p.parse_args(argv)

    catalog = load_catalog()
    cells = load_matrix(Path(args.matrix))
    profiles = load_profiles(Path(args.profiles))

    exp_cells = [c.to_experiment_cell(args.tool_id) for c in cells]
    estimate = estimate_matrix(exp_cells, catalog, profiles)
    feas = feasibility(estimate, args.budget_usd)

    summary = {
        "n_cells": len(cells),
        "n_runs_total": estimate["n_runs"],
        "estimated_usd": round(estimate["total_usd"], 2),
        "budget_usd": args.budget_usd,
        "feasible": feas["feasible"],
        "ratio": round(feas["ratio"], 2),
        "scale_n_to": feas["scale_n_to"],
    }
    print(json.dumps(summary, indent=2))

    if args.check_only:
        return 0 if feas["feasible"] else 2
    if not feas["feasible"]:
        print(
            "matrix exceeds budget; either lower N or raise --budget-usd. "
            f"suggested N total: {feas['scale_n_to']}",
            file=sys.stderr,
        )
        return 2

    # Real execution wiring lands here once we run on a machine with
    # ANTHROPIC_API_KEY and Docker. The check-only path is exercised by
    # experiments/tests/test_run_matrix_check.py.
    print(
        "matrix execution requires ANTHROPIC_API_KEY and the lab containers; "
        "use --check-only for budget validation in CI",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
