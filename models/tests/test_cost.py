from __future__ import annotations

import pytest

from models.cost import (
    ExperimentCell,
    RunCostProfile,
    cost_one_run,
    estimate_matrix,
    feasibility,
)
from models.registry import load_catalog


@pytest.fixture
def catalog():
    return load_catalog()


@pytest.fixture
def profiles():
    """Profiles a test passes explicitly. The library has NO defaults — see
    `paper/04-mock-vs-real.md`. Real values must come from pilot runs."""
    return {
        "shannon-baseline": RunCostProfile(tokens_in=120_000, tokens_out=15_000),
        "shannon-adversarial": RunCostProfile(tokens_in=130_000, tokens_out=18_000),
        "pentestgpt-baseline": RunCostProfile(tokens_in=80_000, tokens_out=10_000),
        "pentestgpt-adversarial": RunCostProfile(tokens_in=88_000, tokens_out=12_000),
        "vulnhuntr-baseline": RunCostProfile(tokens_in=200_000, tokens_out=8_000),
        "vulnhuntr-adversarial": RunCostProfile(tokens_in=215_000, tokens_out=9_000),
        "hackingbuddygpt-baseline": RunCostProfile(tokens_in=60_000, tokens_out=6_000),
        "hackingbuddygpt-adversarial": RunCostProfile(tokens_in=66_000, tokens_out=7_500),
        "autopenbench-baseline": RunCostProfile(tokens_in=90_000, tokens_out=7_000),
        "autopenbench-adversarial": RunCostProfile(tokens_in=98_000, tokens_out=8_500),
    }


def test_cost_one_run_scales_linearly(catalog):
    m = catalog.by_id("claude-opus-4-7")
    p1 = RunCostProfile(tokens_in=10_000, tokens_out=1_000)
    p2 = RunCostProfile(tokens_in=20_000, tokens_out=2_000)
    c1 = cost_one_run(m, p1)
    c2 = cost_one_run(m, p2)
    assert c2 == pytest.approx(2 * c1)


def test_cost_one_run_zero_tokens_is_zero(catalog):
    m = catalog.by_id("claude-opus-4-7")
    assert cost_one_run(m, RunCostProfile(0, 0)) == 0.0


def test_cost_one_run_uses_correct_prices(catalog):
    m = catalog.by_id("claude-opus-4-7")
    p = RunCostProfile(tokens_in=1_000_000, tokens_out=1_000_000)
    expected = m.input_price_per_mtok + m.output_price_per_mtok
    assert cost_one_run(m, p) == pytest.approx(expected)


def test_cost_with_cache_read_discount(catalog):
    m = catalog.by_id("claude-opus-4-7")
    no_cache = RunCostProfile(tokens_in=1_000_000, tokens_out=0)
    with_cache = RunCostProfile(tokens_in=1_000_000, tokens_out=0, cache_read_tokens=500_000)
    assert cost_one_run(m, with_cache) < cost_one_run(m, no_cache)


def test_estimate_matrix_requires_profiles(catalog):
    cells = [ExperimentCell("shannon", "claude-opus-4-7", "baseline", 10)]
    with pytest.raises(ValueError, match="profiles is required"):
        estimate_matrix(cells, catalog, profiles={})


def test_estimate_matrix_aggregates_correctly(catalog, profiles):
    cells = [
        ExperimentCell("shannon", "claude-opus-4-7", "baseline", 10),
        ExperimentCell("shannon", "claude-opus-4-7", "adversarial", 20),
    ]
    out = estimate_matrix(cells, catalog, profiles)
    assert out["n_runs"] == 30
    assert out["by_tool"]["shannon"] == pytest.approx(out["total_usd"])
    assert out["by_model"]["claude-opus-4-7"] == pytest.approx(out["total_usd"])
    assert len(out["by_cell"]) == 2


def test_estimate_matrix_missing_profile_raises(catalog, profiles):
    cells = [ExperimentCell("nonexistent-tool", "claude-opus-4-7", "baseline", 1)]
    with pytest.raises(KeyError, match="no profile"):
        estimate_matrix(cells, catalog, profiles)


def test_feasibility_within_budget(catalog, profiles):
    cells = [ExperimentCell("shannon", "claude-haiku-4-5", "baseline", 5)]
    out = estimate_matrix(cells, catalog, profiles)
    f = feasibility(out, budget_usd=1000.0)
    assert f["feasible"] is True


def test_feasibility_over_budget_suggests_smaller_n(catalog, profiles):
    cells = [ExperimentCell("shannon", "claude-opus-4-7", "baseline", 10_000)]
    out = estimate_matrix(cells, catalog, profiles)
    f = feasibility(out, budget_usd=100.0)
    assert f["feasible"] is False
    assert f["scale_n_to"] < 10_000


def test_full_paper_matrix_estimate_is_reasonable(catalog, profiles):
    cells = []
    tools = [
        ("shannon", "claude-sonnet-4-6"),
        ("pentestgpt", "gpt-4o"),
        ("hackingbuddygpt", "claude-sonnet-4-6"),
        ("vulnhuntr", "gpt-4o"),
        ("autopenbench", "gpt-4o"),
    ]
    for tool_id, model_id in tools:
        for _target in range(5):
            cells.append(ExperimentCell(tool_id, model_id, "baseline", 20))
    for tool_id, model_id in tools:
        for _ in range(5 * 24 * 3):
            cells.append(ExperimentCell(tool_id, model_id, "adversarial", 10))

    out = estimate_matrix(cells, catalog, profiles)
    assert 1_000 < out["total_usd"] < 1_000_000
    assert out["n_runs"] == 5 * 5 * 20 + 5 * 5 * 24 * 3 * 10
