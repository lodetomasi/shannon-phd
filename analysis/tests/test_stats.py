from __future__ import annotations

import numpy as np
import pytest

from analysis.stats import (
    bootstrap_ci,
    cliffs_delta,
    holm_bonferroni,
    mcnemar_exact,
    paired_wilcoxon,
    power_two_proportions,
)


# ---- paired_wilcoxon -------------------------------------------------------

def test_paired_wilcoxon_identical_inputs_is_high_p():
    r = paired_wilcoxon([1.0, 2.0, 3.0], [1.0, 2.0, 3.0])
    assert r.pvalue == 1.0


def test_paired_wilcoxon_clearly_different_is_low_p():
    before = [0.10, 0.12, 0.08, 0.11, 0.09, 0.10, 0.13, 0.12, 0.10, 0.11]
    after = [0.02, 0.03, 0.01, 0.02, 0.03, 0.02, 0.04, 0.02, 0.03, 0.02]
    r = paired_wilcoxon(before, after)
    assert r.pvalue < 0.05
    assert r.n == 10


def test_paired_wilcoxon_mismatched_lengths_raises():
    with pytest.raises(ValueError):
        paired_wilcoxon([1, 2, 3], [1, 2])


# ---- mcnemar_exact ---------------------------------------------------------

def test_mcnemar_no_discordant_pairs():
    r = mcnemar_exact(0, 0)
    assert r.n == 0
    assert r.pvalue == 1.0


def test_mcnemar_perfectly_asymmetric_pairs_is_low_p():
    # 30 cases where defense fixed it, 0 where it broke it -> very strong
    r = mcnemar_exact(b01=30, b10=0)
    assert r.pvalue < 0.001


def test_mcnemar_balanced_discordant_is_high_p():
    r = mcnemar_exact(b01=10, b10=10)
    assert r.pvalue > 0.5


def test_mcnemar_negative_counts_raises():
    with pytest.raises(ValueError):
        mcnemar_exact(-1, 0)


# ---- bootstrap_ci ----------------------------------------------------------

def test_bootstrap_ci_mean_brackets_truth():
    rng = np.random.default_rng(0)
    data = rng.normal(loc=5.0, scale=1.0, size=200)
    ci = bootstrap_ci(data, n_resamples=999)
    assert ci.lo < 5.0 < ci.hi
    assert abs(ci.point - 5.0) < 0.5
    assert ci.confidence == 0.95


def test_bootstrap_ci_too_small_raises():
    with pytest.raises(ValueError):
        bootstrap_ci([1.0])


def test_bootstrap_ci_works_with_median():
    rng = np.random.default_rng(0)
    data = rng.normal(loc=10, scale=2, size=100)
    ci = bootstrap_ci(data, statistic=np.median, n_resamples=999)
    assert ci.lo < 10 < ci.hi


# ---- cliffs_delta ----------------------------------------------------------

def test_cliffs_delta_zero_for_identical_distributions():
    rng = np.random.default_rng(0)
    a = rng.normal(0, 1, 100)
    b = rng.normal(0, 1, 100)
    d = cliffs_delta(a, b)
    assert abs(d) < 0.15  # negligible


def test_cliffs_delta_positive_when_a_dominates():
    a = [10, 11, 12, 13, 14]
    b = [1, 2, 3, 4, 5]
    assert cliffs_delta(a, b) == 1.0


def test_cliffs_delta_negative_when_b_dominates():
    a = [1, 2, 3]
    b = [10, 11, 12]
    assert cliffs_delta(a, b) == -1.0


def test_cliffs_delta_empty_raises():
    with pytest.raises(ValueError):
        cliffs_delta([], [1, 2])


# ---- holm_bonferroni -------------------------------------------------------

def test_holm_no_pvalues_returns_empty():
    assert holm_bonferroni({}) == []


def test_holm_single_pvalue_unchanged():
    [r] = holm_bonferroni({"x": 0.01})
    assert r.adjusted == pytest.approx(0.01)
    assert r.rejected is True


def test_holm_step_down_monotone():
    pvals = {"a": 0.001, "b": 0.01, "c": 0.04, "d": 0.20}
    out = holm_bonferroni(pvals, alpha=0.05)
    # adjusted values must be monotonically non-decreasing
    adj = [r.adjusted for r in out]
    assert adj == sorted(adj)
    # `a` clearly significant; `d` clearly not
    by_label = {r.label: r for r in out}
    assert by_label["a"].rejected is True
    assert by_label["d"].rejected is False


def test_holm_24_classes_simulation():
    """Realistic case: 24 payload classes, half significant."""
    pvals = {f"c{i}": 0.001 if i < 12 else 0.5 for i in range(24)}
    out = holm_bonferroni(pvals, alpha=0.05)
    rejected = [r for r in out if r.rejected]
    assert len(rejected) == 12


# ---- power_two_proportions -------------------------------------------------

def test_power_smaller_effect_needs_larger_n():
    n_small = power_two_proportions(0.10, 0.05)
    n_smaller = power_two_proportions(0.10, 0.08)
    assert n_smaller > n_small


def test_power_typical_paper_values():
    # Detecting ASR drop from 50% to 30% with α=0.05, power=0.80
    n = power_two_proportions(0.50, 0.30)
    # Sanity: should be in the ~90s per group, not 5 or 5000.
    assert 50 < n < 200


def test_power_equal_proportions_raises():
    with pytest.raises(ValueError):
        power_two_proportions(0.5, 0.5)


def test_power_invalid_proportions_raise():
    with pytest.raises(ValueError):
        power_two_proportions(0.0, 0.5)
    with pytest.raises(ValueError):
        power_two_proportions(0.5, 1.0)
