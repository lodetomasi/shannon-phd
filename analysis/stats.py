"""Statistical tests required by Rank A* venues.

We use scipy where its API gives us what we need; everything else is a
small, tested wrapper.

What's here:
  - paired_wilcoxon: paired Wilcoxon signed-rank — for ASR pre/post defense, etc.
  - mcnemar_exact:   exact McNemar on a 2×2 contingency for paired binary outcomes.
  - bootstrap_ci:    BCa 95% CI for an arbitrary statistic over independent samples.
  - cliffs_delta:    non-parametric effect size for two independent samples.
  - holm_bonferroni: family-wise correction across the 24 payload classes.
  - power_two_proportions: minimum n per group for given (p1, p2, alpha, power).

All functions return small dataclasses or named tuples — no bare floats —
so reviewers can see what was computed and the analysis notebook stays readable.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

import numpy as np
from scipy import stats


@dataclass(frozen=True)
class TestResult:
    statistic: float
    pvalue: float
    n: int
    note: str = ""


@dataclass(frozen=True)
class CIResult:
    point: float
    lo: float
    hi: float
    confidence: float


def paired_wilcoxon(
    before: Sequence[float],
    after: Sequence[float],
    alternative: str = "two-sided",
) -> TestResult:
    """Paired Wilcoxon signed-rank. Use for: ASR pre/post defense, PRS comparison, etc."""
    a = np.asarray(before, dtype=float)
    b = np.asarray(after, dtype=float)
    if len(a) != len(b):
        raise ValueError("paired_wilcoxon requires same-length sequences")
    if len(a) < 1:
        raise ValueError("paired_wilcoxon requires at least one pair")
    diffs = a - b
    if np.all(diffs == 0):
        return TestResult(statistic=0.0, pvalue=1.0, n=len(a), note="all differences zero")
    res = stats.wilcoxon(a, b, alternative=alternative, zero_method="wilcox")
    return TestResult(
        statistic=float(res.statistic),
        pvalue=float(res.pvalue),
        n=len(a),
        note=f"alternative={alternative}",
    )


def mcnemar_exact(
    b01: int,
    b10: int,
) -> TestResult:
    """Exact McNemar test on discordant pairs.

    `b01` = pairs where 1st condition succeeded but 2nd failed.
    `b10` = pairs where 1st failed but 2nd succeeded.
    Concordant pairs do not enter the test (that's the point).

    Use for: same payload, did the tool report finding X under defense vs no defense?
    """
    if b01 < 0 or b10 < 0:
        raise ValueError("counts must be non-negative")
    n = b01 + b10
    if n == 0:
        return TestResult(0.0, 1.0, 0, note="no discordant pairs")
    # Two-sided exact binomial test on min(b01, b10) ~ Binomial(n, 0.5)
    k = min(b01, b10)
    res = stats.binomtest(k=k, n=n, p=0.5, alternative="two-sided")
    return TestResult(
        statistic=float(k),
        pvalue=float(res.pvalue),
        n=n,
        note=f"discordant=(b01={b01}, b10={b10})",
    )


def bootstrap_ci(
    data: Sequence[float],
    statistic: Callable[[np.ndarray], float] = np.mean,
    confidence: float = 0.95,
    n_resamples: int = 9999,
    seed: int | None = 42,
) -> CIResult:
    """BCa bootstrap CI via scipy.stats.bootstrap.

    Default statistic is the mean — pass np.median or a custom callable for others.
    """
    arr = np.asarray(data, dtype=float)
    if arr.size < 2:
        raise ValueError("bootstrap_ci needs ≥2 observations")
    rng = np.random.default_rng(seed)
    res = stats.bootstrap(
        (arr,),
        statistic,
        confidence_level=confidence,
        n_resamples=n_resamples,
        method="BCa",
        random_state=rng,
    )
    return CIResult(
        point=float(statistic(arr)),
        lo=float(res.confidence_interval.low),
        hi=float(res.confidence_interval.high),
        confidence=confidence,
    )


def cliffs_delta(a: Sequence[float], b: Sequence[float]) -> float:
    """Cliff's delta — non-parametric effect size in [-1, 1].

    Interpretation thresholds (Romano et al. 2006): |δ|<0.147 negligible,
    <0.33 small, <0.474 medium, ≥0.474 large.
    """
    x = np.asarray(a, dtype=float)
    y = np.asarray(b, dtype=float)
    if x.size == 0 or y.size == 0:
        raise ValueError("cliffs_delta requires non-empty inputs")
    # Pairwise comparison via broadcasting; OK for the sizes we'll see (≤ 1000).
    diff = x[:, None] - y[None, :]
    n_gt = np.sum(diff > 0)
    n_lt = np.sum(diff < 0)
    return float((n_gt - n_lt) / (x.size * y.size))


@dataclass(frozen=True)
class AdjustedPValue:
    raw: float
    adjusted: float
    rejected: bool
    label: str


def holm_bonferroni(pvalues: dict[str, float], alpha: float = 0.05) -> list[AdjustedPValue]:
    """Holm-Bonferroni step-down correction.

    Input: dict mapping a label (e.g. payload class) to its raw p-value.
    Output: list ordered by adjusted p, with reject/no-reject under FWER ≤ alpha.
    """
    if not pvalues:
        return []
    items = sorted(pvalues.items(), key=lambda kv: kv[1])
    m = len(items)
    out: list[AdjustedPValue] = []
    running_max = 0.0
    for i, (label, p) in enumerate(items):
        adj = (m - i) * p
        adj = min(1.0, max(running_max, adj))
        running_max = adj
        out.append(AdjustedPValue(raw=p, adjusted=adj, rejected=adj <= alpha, label=label))
    return out


def power_two_proportions(
    p1: float,
    p2: float,
    alpha: float = 0.05,
    power: float = 0.80,
) -> int:
    """Minimum n PER GROUP for two-proportion test (two-sided).

    Standard formula:
      n = (z_{1-α/2} √(2 p̄ q̄) + z_{power} √(p1 q1 + p2 q2))² / (p1 - p2)²

    Use for sizing N runs needed to detect a target ASR difference.
    """
    if not (0 < p1 < 1) or not (0 < p2 < 1):
        raise ValueError("p1, p2 must be in (0, 1)")
    if p1 == p2:
        raise ValueError("p1 must differ from p2 for power to be defined")
    z_alpha = stats.norm.ppf(1 - alpha / 2)
    z_power = stats.norm.ppf(power)
    p_bar = (p1 + p2) / 2
    q_bar = 1 - p_bar
    q1, q2 = 1 - p1, 1 - p2
    numerator = (z_alpha * np.sqrt(2 * p_bar * q_bar) + z_power * np.sqrt(p1 * q1 + p2 * q2)) ** 2
    denominator = (p1 - p2) ** 2
    return int(np.ceil(numerator / denominator))
