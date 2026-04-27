"""Final analysis pipeline — produces publication-ready stats + figures.

Reads:
  - results/rq1-combined.jsonl   (165 runs, prior round)
  - results/rq-full-round.jsonl  (~225 runs, this round)

Outputs:
  - results/all-runs.jsonl                merged dataset
  - results/rq1-stats-final.json          paired Wilcoxon per model
  - results/rq2-channel-stats.json        channel comparison (Mistral)
  - results/rq4-spearman.json             capability inversion
  - figures/rq1-final-v2/*.{pdf,png}      bar/heatmap/lineplot
  - figures/rq2-channels/*.{pdf,png}      vector-comparison bar
  - results/results-table.md              human-readable summary
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy import stats as scistats

from analysis.classifier import classify_output
from analysis.plots import render_all_figures, severity_by_condition_bar
from analysis.stats import paired_wilcoxon


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


def merge_datasets(paper_dir: Path) -> Path:
    """Combine prior + new runs. Re-classify everything for consistency."""
    prior = load_jsonl(paper_dir / "results" / "rq1-combined.jsonl")
    new = load_jsonl(paper_dir / "results" / "rq-full-round.jsonl")
    merged = []
    for r in prior + new:
        # Re-classify with current classifier so we never compare across versions.
        if "final_text" in r:
            r["classification"] = classify_output(r["final_text"])
        merged.append(r)
    out = paper_dir / "results" / "all-runs.jsonl"
    with out.open("w", encoding="utf-8") as f:
        for r in merged:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")
    print(f"Merged dataset: {len(merged)} runs → {out}")
    return out


def rq1_stats(records: list[dict], paper_dir: Path) -> dict:
    """Paired Wilcoxon baseline vs authority per model. RQ1 main finding."""
    by_cell: dict[tuple, list[int]] = defaultdict(list)
    for r in records:
        cond = r.get("condition", "")
        if cond not in {"baseline", "authority"}:
            continue
        by_cell[(r["label"], cond)].append(r["classification"]["sqli_severity"])

    out = []
    for label in sorted({k[0] for k in by_cell}):
        b = by_cell.get((label, "baseline"), [])
        a = by_cell.get((label, "authority"), [])
        if len(b) < 2 or len(a) < 2:
            continue
        n = min(len(b), len(a))
        try:
            res = paired_wilcoxon(b[:n], a[:n])
            stat, p = res.statistic, res.pvalue
        except Exception:
            stat, p = float("nan"), float("nan")
        out.append({
            "model": label, "n": n,
            "mean_baseline": float(np.mean(b[:n])),
            "mean_authority": float(np.mean(a[:n])),
            "delta": float(np.mean(a[:n]) - np.mean(b[:n])),
            "wilcoxon_W": float(stat),
            "p_value": float(p),
            "significant_05": bool(p < 0.05),
        })
    p = paper_dir / "results" / "rq1-stats-final.json"
    p.write_text(json.dumps(out, indent=2))
    print(f"RQ1 stats → {p}")
    return out


def rq2_channel_stats(records: list[dict], paper_dir: Path) -> dict:
    """Compare ASR (severity drop) across the 6 vectors on Mistral."""
    # Tier-3 records have condition starting with "rq2-{vector}-injected"
    by_vec: dict[str, list[int]] = defaultdict(list)
    base = []
    for r in records:
        if r.get("label") != "mistral-large":
            continue
        cond = r.get("condition", "")
        sev = r["classification"]["sqli_severity"]
        if cond == "baseline":
            base.append(sev)
        elif cond.startswith("rq2-") and cond.endswith("-injected"):
            vec = cond.replace("rq2-", "").replace("-injected", "")
            by_vec[vec].append(sev)
        elif cond == "authority":
            by_vec["code-comment"].append(sev)
    base_mean = float(np.mean(base)) if base else float("nan")
    out = {"baseline_mean_sqli_severity": base_mean,
           "by_vector": {}}
    for vec, vals in by_vec.items():
        out["by_vector"][vec] = {
            "n": len(vals),
            "mean": float(np.mean(vals)),
            "delta_vs_baseline": float(np.mean(vals)) - base_mean,
        }
    p = paper_dir / "results" / "rq2-channel-stats.json"
    p.write_text(json.dumps(out, indent=2))
    print(f"RQ2 channel stats → {p}")
    return out


def rq4_spearman(rq1_rows: list[dict], paper_dir: Path) -> dict:
    """Spearman ρ between capability proxy and Δ severity."""
    cap_proxy = {
        "haiku-3":         0.25,
        "qwen-80b":        1.50,
        "qwen-235b":       2.00,
        "mistral-large":   4.00,
        "gpt-oss-120b":    0.50,
        "minimax-2.5":     1.00,
        "devstral-123b":   2.50,
        "gemma-3-4b":      0.05,
        "ministral-3b":    0.05,
        "ministral-8b":    0.10,
    }
    pts = []
    for row in rq1_rows:
        if row["model"] in cap_proxy:
            pts.append((cap_proxy[row["model"]], row["delta"], row["model"]))
    if len(pts) < 4:
        out = {"rho": None, "p": None, "n": len(pts), "points": pts}
    else:
        rho, p = scistats.spearmanr([x for x, _, _ in pts], [y for _, y, _ in pts])
        out = {"rho": float(rho), "p": float(p), "n": len(pts),
               "points": [{"model": m, "capability": x, "delta": y}
                          for x, y, m in pts]}
    p = paper_dir / "results" / "rq4-spearman.json"
    p.write_text(json.dumps(out, indent=2))
    print(f"RQ4 Spearman → {p}")
    return out


def write_results_table(rq1: list[dict], rq2: dict, rq4: dict,
                        paper_dir: Path) -> Path:
    """Human-readable + LaTeX-friendly results summary."""
    lines = ["# RQ Results Summary (auto-generated)\n"]
    lines.append("## RQ1 — Paired Wilcoxon baseline vs authority (per model)\n")
    lines.append("| Model | N | μ baseline | μ authority | Δ | W | p | sig |")
    lines.append("|-------|---|-----------|-------------|----|---|---|-----|")
    for r in sorted(rq1, key=lambda x: x["delta"]):
        sig = "***" if r["p_value"] < 0.001 else "**" if r["p_value"] < 0.01 else "*" if r["p_value"] < 0.05 else "ns"
        lines.append(
            f"| {r['model']} | {r['n']} | {r['mean_baseline']:.2f} | "
            f"{r['mean_authority']:.2f} | {r['delta']:+.2f} | "
            f"{r['wilcoxon_W']:.1f} | {r['p_value']:.4f} | {sig} |"
        )
    lines.append("")

    lines.append("## RQ2 — Channel comparison on Mistral-Large\n")
    lines.append(f"Baseline mean SQLi severity: **{rq2['baseline_mean_sqli_severity']:.2f}**\n")
    lines.append("| Vector | N | μ severity | Δ vs baseline |")
    lines.append("|--------|---|-----------|----------------|")
    for vec, st in sorted(rq2["by_vector"].items(),
                          key=lambda kv: kv[1]["delta_vs_baseline"]):
        lines.append(f"| {vec} | {st['n']} | {st['mean']:.2f} | {st['delta_vs_baseline']:+.2f} |")
    lines.append("")

    lines.append("## RQ4 — Capability proxy vs severity Δ (Spearman)\n")
    if rq4["rho"] is not None:
        lines.append(f"Spearman ρ = **{rq4['rho']:.3f}**, p = **{rq4['p']:.3f}**, "
                     f"N = {rq4['n']} models\n")
        lines.append("| Model | Capability ($/MTok in) | Δ severity |")
        lines.append("|-------|-----------------------|------------|")
        for pt in sorted(rq4["points"], key=lambda x: x["capability"]):
            lines.append(f"| {pt['model']} | {pt['capability']:.2f} | {pt['delta']:+.2f} |")
    else:
        lines.append("Not enough points for Spearman.\n")
    lines.append("")
    out = paper_dir / "results" / "results-table.md"
    out.write_text("\n".join(lines))
    print(f"Summary table → {out}")
    return out


def render_figures(merged_path: Path, paper_dir: Path) -> list[Path]:
    out_dir = paper_dir / "figures" / "rq1-final-v2"
    return render_all_figures(merged_path, out_dir)


def main(paper_dir: Path) -> None:
    merged = merge_datasets(paper_dir)
    records = load_jsonl(merged)
    rq1 = rq1_stats(records, paper_dir)
    rq2 = rq2_channel_stats(records, paper_dir)
    rq4 = rq4_spearman(rq1, paper_dir)
    write_results_table(rq1, rq2, rq4, paper_dir)
    figs = render_figures(merged, paper_dir)
    print(f"\nFigures: {len(figs)} files")
    print("Done.")


if __name__ == "__main__":
    import sys
    paper = Path(__file__).resolve().parents[1]
    main(paper)
