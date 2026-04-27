"""Cost estimation for the experimental matrix.

Used by 01-experimental-plan.md to check whether a power-analysis-derived
N is feasible within budget.

There are NO default token profiles. The caller passes a `profiles` dict
calibrated from real pilot runs. If a cell has no profile we raise — never
silently use a guess. This is deliberate: see `paper/04-mock-vs-real.md`.
"""
from __future__ import annotations

from dataclasses import dataclass

from .registry import Catalog, Model


@dataclass(frozen=True)
class RunCostProfile:
    """Average per-run token usage for a given (tool, condition).

    Calibrate from real pilot runs in M1 — typically the median of ≥10 runs.
    """
    tokens_in: int
    tokens_out: int
    cache_read_tokens: int = 0


def cost_one_run(model: Model, profile: RunCostProfile) -> float:
    """Cost in USD for one execution at given token usage."""
    in_cost = (profile.tokens_in - profile.cache_read_tokens) / 1_000_000 * model.input_price_per_mtok
    out_cost = profile.tokens_out / 1_000_000 * model.output_price_per_mtok
    cache_cost = 0.0
    if profile.cache_read_tokens and model.cache_read_price_per_mtok is not None:
        cache_cost = profile.cache_read_tokens / 1_000_000 * model.cache_read_price_per_mtok
    return in_cost + out_cost + cache_cost


@dataclass(frozen=True)
class ExperimentCell:
    """A single (tool, model, condition) experimental cell with run count."""
    tool_id: str
    model_id: str
    condition: str        # e.g. "baseline" or "adversarial"
    n_runs: int

    def profile_key(self) -> str:
        return f"{self.tool_id}-{self.condition}"


def estimate_matrix(
    cells: list[ExperimentCell],
    catalog: Catalog,
    profiles: dict[str, RunCostProfile],
) -> dict:
    """Total + per-cell cost for an experimental matrix.

    `profiles` is REQUIRED — there are no defaults. Each cell's
    `profile_key()` must exist in `profiles` or we raise.

    Returns a dict with: total_usd, by_cell (list), by_model (dict),
    by_tool (dict), n_runs.
    """
    if not profiles:
        raise ValueError(
            "profiles is required and must be non-empty. Calibrate from "
            "real pilot runs (M1) before estimating the matrix."
        )
    total = 0.0
    by_cell = []
    by_model: dict[str, float] = {}
    by_tool: dict[str, float] = {}
    for cell in cells:
        model = catalog.by_id(cell.model_id)
        prof = profiles.get(cell.profile_key())
        if prof is None:
            raise KeyError(
                f"no profile for {cell.profile_key()!r}; calibrate it from "
                f"real pilot runs and pass it explicitly"
            )
        per_run = cost_one_run(model, prof)
        cell_total = per_run * cell.n_runs
        total += cell_total
        by_cell.append({
            "cell": cell,
            "per_run_usd": per_run,
            "total_usd": cell_total,
        })
        by_model[cell.model_id] = by_model.get(cell.model_id, 0.0) + cell_total
        by_tool[cell.tool_id] = by_tool.get(cell.tool_id, 0.0) + cell_total
    return {
        "total_usd": total,
        "by_cell": by_cell,
        "by_model": by_model,
        "by_tool": by_tool,
        "n_runs": sum(c.n_runs for c in cells),
    }


def feasibility(estimate: dict, budget_usd: float) -> dict:
    """Compare estimate against budget. Returns ratio + scale_n_to hint."""
    total = estimate["total_usd"]
    over = total > budget_usd
    return {
        "total_usd": total,
        "budget_usd": budget_usd,
        "ratio": total / budget_usd if budget_usd > 0 else float("inf"),
        "feasible": not over,
        "scale_n_to": (
            int(estimate["n_runs"] * budget_usd / total)
            if over and total > 0 else estimate["n_runs"]
        ),
    }
