"""Robustness checks for the published findings.

Re-processes all run telemetry and produces:
  - Bonferroni / Holm-corrected p-values across the family of tests
  - BCa bootstrap 95% CI for every Δ
  - Cohen's d effect size for every comparison
  - Permutation test (label shuffle) for non-parametric robust p
  - RQ4 Spearman recomputed excluding capability-gap models (baseline μ < 2)
  - Stability check: split N=20 into two halves, do they agree?

Output: results/robustness-summary.json + a markdown table.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy import stats as scistats

from analysis.classifier import classify_output
from analysis.stats import bootstrap_ci, holm_bonferroni, paired_wilcoxon


def load_jsonl(p: Path) -> list[dict]:
    if not p.is_file():
        return []
    out = []
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def reclassify(records: list[dict]) -> list[dict]:
    for r in records:
        if "final_text" in r:
            r["classification"] = classify_output(r["final_text"])
    return records


def cohens_d(a: list[float], b: list[float]) -> float:
    """Pooled-SD Cohen's d. Positive = a > b."""
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    if a.size < 2 or b.size < 2:
        return float("nan")
    n1, n2 = a.size, b.size
    s1, s2 = a.std(ddof=1), b.std(ddof=1)
    pooled = np.sqrt(((n1 - 1) * s1 ** 2 + (n2 - 1) * s2 ** 2) / (n1 + n2 - 2))
    if pooled == 0:
        return 0.0
    return float((a.mean() - b.mean()) / pooled)


def permutation_test(a: list[float], b: list[float],
                     n_perm: int = 9999, seed: int = 42) -> float:
    """Two-sided permutation test of mean difference. Returns p-value."""
    rng = np.random.default_rng(seed)
    arr_a = np.asarray(a, dtype=float)
    arr_b = np.asarray(b, dtype=float)
    obs = abs(arr_a.mean() - arr_b.mean())
    pool = np.concatenate([arr_a, arr_b])
    n_a = arr_a.size
    count = 0
    for _ in range(n_perm):
        rng.shuffle(pool)
        diff = abs(pool[:n_a].mean() - pool[n_a:].mean())
        if diff >= obs:
            count += 1
    return (count + 1) / (n_perm + 1)


def main() -> None:
    paper = Path(__file__).resolve().parents[1]
    all_records = []
    for fname in ("all-runs.jsonl", "rq3-ablation-edge.jsonl"):
        all_records.extend(load_jsonl(paper / "results" / fname))
    all_records = reclassify(all_records)
    print(f"Loaded {len(all_records)} runs total.")

    # ------------------------------------------------------------------
    # Cell aggregation: (label, condition_or_cell)
    # ------------------------------------------------------------------
    cells: dict[tuple, list[int]] = defaultdict(list)
    for r in all_records:
        if r.get("label") is None:
            continue
        sev = r.get("classification", {}).get("sqli_severity")
        if sev is None:
            continue
        # The "cell" key is whichever experimental group applies.
        ckey = r.get("cell") or r.get("condition") or "unknown"
        cells[(r["label"], ckey)].append(int(sev))

    # ------------------------------------------------------------------
    # RQ1: paired comparisons baseline vs authority for each model.
    # ------------------------------------------------------------------
    print("\n" + "=" * 100)
    print("RQ1 with full robustness battery")
    print("=" * 100)
    print(f"  {'model':16s}  {'n_b':>4s}  {'n_a':>4s}  {'μ_b':>5s}  {'μ_a':>5s}  "
          f"{'Δ':>6s}  {'CI95':>16s}  {'cohen_d':>7s}  "
          f"{'wilcox p':>9s}  {'perm p':>8s}")
    rq1_results = []
    rq1_pvals: dict[str, float] = {}
    for label in sorted({k[0] for k in cells}):
        b = cells.get((label, "baseline"), [])
        a = cells.get((label, "authority"), [])
        if len(b) < 3 or len(a) < 3:
            continue
        n_pair = min(len(b), len(a))
        try:
            wres = paired_wilcoxon(b[:n_pair], a[:n_pair])
            wp = wres.pvalue
        except Exception:
            wp = float("nan")
        try:
            perm_p = permutation_test(b, a, n_perm=2999)
        except Exception:
            perm_p = float("nan")
        # bootstrap CI on Δ
        try:
            diffs = np.array(a[:n_pair]) - np.array(b[:n_pair])
            ci = bootstrap_ci(list(diffs), n_resamples=2999)
            ci_str = f"[{ci.lo:+.2f},{ci.hi:+.2f}]"
        except Exception:
            ci_str = "—"
        d = cohens_d(a, b)
        delta = float(np.mean(a) - np.mean(b))
        rq1_results.append({
            "model": label, "n_baseline": len(b), "n_authority": len(a),
            "mean_baseline": float(np.mean(b)),
            "mean_authority": float(np.mean(a)),
            "delta": delta, "ci_str": ci_str,
            "cohen_d": d, "wilcoxon_p": wp, "permutation_p": perm_p,
            "capability_gap": float(np.mean(b)) < 2.0,
        })
        rq1_pvals[label] = wp
        print(f"  {label:16s}  {len(b):>4d}  {len(a):>4d}  "
              f"{np.mean(b):>5.2f}  {np.mean(a):>5.2f}  "
              f"{delta:>+6.2f}  {ci_str:>16s}  {d:>+7.2f}  "
              f"{wp:>9.4f}  {perm_p:>8.4f}")

    # Holm-Bonferroni across the family of RQ1 p-values.
    adj = holm_bonferroni(rq1_pvals, alpha=0.05)
    print("\n  Holm-Bonferroni adjusted p-values:")
    for a in adj:
        print(f"    {a.label:16s}  raw={a.raw:.4f}  adj={a.adjusted:.4f}  "
              f"reject={'YES' if a.rejected else 'no'}")

    # ------------------------------------------------------------------
    # RQ4 Spearman with capability-gap exclusion.
    # ------------------------------------------------------------------
    print("\n" + "=" * 100)
    print("RQ4 Spearman — full vs capability-gap-excluded")
    print("=" * 100)
    cap_proxy = {
        "haiku-3": 0.25, "qwen-80b": 1.50, "qwen-235b": 2.00, "mistral-large": 4.00,
        "gpt-oss-120b": 0.50, "minimax-2.5": 1.00, "devstral-123b": 2.50,
        "gemma-3-4b": 0.05, "ministral-3b": 0.05, "ministral-8b": 0.10,
    }
    for excl in (False, True):
        pts = []
        for r in rq1_results:
            if r["model"] not in cap_proxy:
                continue
            if excl and r["capability_gap"]:
                continue
            pts.append((cap_proxy[r["model"]], r["delta"], r["model"]))
        if len(pts) >= 3:
            rho, p = scistats.spearmanr([x for x, _, _ in pts], [y for _, y, _ in pts])
            label = "EXCL capability-gap" if excl else "FULL N"
            print(f"  {label:25s}  N={len(pts)}  ρ={rho:+.3f}  p={p:.3f}")
            for cap, dlt, mn in sorted(pts, key=lambda x: x[0]):
                print(f"    {mn:18s}  cap={cap:.2f}  Δ={dlt:+.2f}")

    # ------------------------------------------------------------------
    # Internal stability: split N=20 mistral-large pair into two halves.
    # ------------------------------------------------------------------
    print("\n" + "=" * 100)
    print("Stability check: split mistral-large N=20 into two halves")
    print("=" * 100)
    m_b = cells.get(("mistral-large", "baseline"), [])
    m_a = cells.get(("mistral-large", "authority"), [])
    if len(m_b) >= 10 and len(m_a) >= 10:
        h1_b, h2_b = m_b[: len(m_b)//2], m_b[len(m_b)//2:]
        h1_a, h2_a = m_a[: len(m_a)//2], m_a[len(m_a)//2:]
        for tag, bb, aa in [("half-1", h1_b, h1_a), ("half-2", h2_b, h2_a)]:
            d = float(np.mean(aa) - np.mean(bb))
            try:
                w = paired_wilcoxon(bb[:len(aa)], aa).pvalue
            except Exception:
                w = float("nan")
            print(f"  {tag:8s}  n={len(bb)}+{len(aa)}  "
                  f"μ_b={np.mean(bb):.2f}  μ_a={np.mean(aa):.2f}  "
                  f"Δ={d:+.2f}  wilcox p={w:.4f}")

    # ------------------------------------------------------------------
    # Save summary.
    # ------------------------------------------------------------------
    out = paper / "results" / "robustness-summary.json"
    out.write_text(json.dumps({
        "rq1": rq1_results,
        "holm_bonferroni": [a.__dict__ for a in adj],
    }, indent=2, default=str))
    print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
