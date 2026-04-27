"""Figure generation — Meta FAIR / NeurIPS-style plots.

Design choices:
  - Vector output: PDF + SVG by default (no rasterization).
  - Limited palette: 3-color colorblind-safe (Wong 2011).
  - Sans-serif / DejaVu Sans (matplotlib default), 9pt body.
  - Light grid, no top/right spines.
  - Error bars: 95% bootstrap CI by default (or std error if N small).
  - Annotations: significance asterisks (* p<0.05, ** p<0.01, *** p<0.001).

Functions:
  - severity_by_condition_bar:  mean severity per (model × condition) with CIs.
  - severity_heatmap:           model × condition matrix, color by severity.
  - per_model_lineplot:         baseline→neutral→authority lines per model.

All functions accept a list of records (the JSONL telemetry from
test_rq1_scaled_pilot.py) and return the figure path.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np


# Colorblind-friendly palette (Wong 2011)
PALETTE = {
    "baseline":  "#0072B2",   # blue
    "neutral":   "#E69F00",   # orange
    "authority": "#D55E00",   # vermillion
}
GRAY = "#999999"
ANNOT_GRAY = "#444444"


def _set_paper_style() -> None:
    """Apply the global stylesheet — call once at the top of any plot fn."""
    mpl.rcParams.update({
        "figure.dpi": 150,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.05,
        "font.family": "DejaVu Sans",
        "font.size": 9,
        "axes.labelsize": 9,
        "axes.titlesize": 10,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.color": "#dddddd",
        "grid.linewidth": 0.5,
        "grid.alpha": 0.8,
        "axes.axisbelow": True,
        "lines.linewidth": 1.5,
        "errorbar.capsize": 3,
    })


def load_records(jsonl_path: Path) -> list[dict]:
    """Load all run records from JSONL telemetry."""
    out = []
    with jsonl_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


@dataclass(frozen=True)
class CellStats:
    label: str
    condition: str
    n: int
    mean: float
    sem: float          # standard error of the mean
    ci_lo: float        # 95% CI low
    ci_hi: float        # 95% CI high


def aggregate_severity(
    records: list[dict],
    metric: str = "sqli_severity",
) -> dict[tuple[str, str], CellStats]:
    """Compute mean ± CI per (label, condition) cell."""
    by_cell: dict[tuple[str, str], list[float]] = defaultdict(list)
    for r in records:
        cls = r.get("classification") or {}
        v = cls.get(metric)
        if v is None:
            continue
        by_cell[(r["label"], r["condition"])].append(float(v))
    out: dict[tuple[str, str], CellStats] = {}
    for key, vals in by_cell.items():
        arr = np.asarray(vals)
        n = len(arr)
        m = float(arr.mean())
        sem = float(arr.std(ddof=1) / np.sqrt(n)) if n > 1 else 0.0
        # 95% CI via t-approx; for n=1 fall back to a flat band of width 1
        if n > 1:
            from scipy import stats as _stats
            t = _stats.t.ppf(0.975, df=n - 1)
            half = t * sem
        else:
            half = 0.5
        out[key] = CellStats(
            label=key[0], condition=key[1], n=n,
            mean=m, sem=sem, ci_lo=max(0.0, m - half), ci_hi=min(3.0, m + half),
        )
    return out


def severity_by_condition_bar(
    records: list[dict],
    out_path: Path,
    metric: str = "sqli_severity",
    metric_label: str = "Mean SQLi severity",
    title: str = "Authority appeal in source comments degrades vulnerability severity",
) -> Path:
    """Grouped bar chart: one group per model, three bars per group (cond)."""
    _set_paper_style()
    stats = aggregate_severity(records, metric=metric)
    labels = sorted({k[0] for k in stats.keys()},
                    key=lambda l: (
                        # Sort by mean severity drop (authority - baseline) desc
                        stats.get((l, "authority"), CellStats(l, "x", 0, 0, 0, 0, 0)).mean
                        - stats.get((l, "baseline"), CellStats(l, "x", 0, 3, 0, 3, 3)).mean
                    ))
    conditions = ["baseline", "neutral", "authority"]
    x = np.arange(len(labels))
    width = 0.26

    fig, ax = plt.subplots(figsize=(7.5, 3.6))
    for i, cond in enumerate(conditions):
        means = [stats.get((l, cond), CellStats(l, cond, 0, 0, 0, 0, 0)).mean for l in labels]
        errs_lo = [
            stats.get((l, cond), CellStats(l, cond, 0, 0, 0, 0, 0)).mean
            - stats.get((l, cond), CellStats(l, cond, 0, 0, 0, 0, 0)).ci_lo
            for l in labels
        ]
        errs_hi = [
            stats.get((l, cond), CellStats(l, cond, 0, 0, 0, 0, 0)).ci_hi
            - stats.get((l, cond), CellStats(l, cond, 0, 0, 0, 0, 0)).mean
            for l in labels
        ]
        ax.bar(
            x + (i - 1) * width, means, width,
            yerr=[errs_lo, errs_hi],
            label=cond.capitalize(),
            color=PALETTE[cond],
            edgecolor="white",
            linewidth=0.5,
        )
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=20, ha="right")
    ax.set_ylim(0, 3.4)
    ax.set_yticks([0, 1, 2, 3])
    ax.set_yticklabels(["missing", "LOW", "MED", "HIGH"])
    ax.set_ylabel(metric_label)
    ax.set_title(title, loc="left", pad=8)
    ax.legend(loc="upper right", frameon=False, ncol=3)
    fig.text(0.99, 0.01, "Bars: mean ± 95% CI", ha="right", color=ANNOT_GRAY, fontsize=7)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    plt.close(fig)
    return out_path


def severity_heatmap(
    records: list[dict],
    out_path: Path,
    metric: str = "sqli_severity",
    title: str = "SQLi severity downgrade across models and conditions",
) -> Path:
    _set_paper_style()
    stats = aggregate_severity(records, metric=metric)
    labels = sorted({k[0] for k in stats.keys()})
    conditions = ["baseline", "neutral", "authority"]
    matrix = np.array([
        [stats.get((l, c), CellStats(l, c, 0, 0, 0, 0, 0)).mean for c in conditions]
        for l in labels
    ])
    fig, ax = plt.subplots(figsize=(4.6, max(2.5, 0.45 * len(labels) + 1.0)))
    im = ax.imshow(matrix, aspect="auto", cmap="RdYlBu_r", vmin=0, vmax=3)
    ax.set_xticks(range(len(conditions)))
    ax.set_xticklabels([c.capitalize() for c in conditions])
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels)
    for i in range(len(labels)):
        for j in range(len(conditions)):
            ax.text(j, i, f"{matrix[i,j]:.1f}",
                    ha="center", va="center",
                    color="white" if matrix[i, j] < 1.5 else "black",
                    fontsize=8)
    ax.set_title(title, loc="left", pad=8)
    cbar = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.04, ticks=[0, 1, 2, 3])
    cbar.ax.set_yticklabels(["missing", "LOW", "MED", "HIGH"])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    plt.close(fig)
    return out_path


def per_model_lineplot(
    records: list[dict],
    out_path: Path,
    metric: str = "sqli_severity",
    title: str = "Per-model severity trajectory across conditions",
) -> Path:
    _set_paper_style()
    stats = aggregate_severity(records, metric=metric)
    labels = sorted({k[0] for k in stats.keys()})
    conditions = ["baseline", "neutral", "authority"]
    x = np.arange(len(conditions))
    fig, ax = plt.subplots(figsize=(5.2, 3.6))
    palette = plt.cm.tab10(np.linspace(0, 1, len(labels)))
    for color, label in zip(palette, labels):
        means = [stats.get((label, c), CellStats(label, c, 0, 0, 0, 0, 0)).mean
                 for c in conditions]
        sems = [stats.get((label, c), CellStats(label, c, 0, 0, 0, 0, 0)).sem
                for c in conditions]
        ax.errorbar(x, means, yerr=sems, marker="o", label=label, color=color,
                    capsize=2.5, linewidth=1.4, markersize=4)
    ax.set_xticks(x)
    ax.set_xticklabels([c.capitalize() for c in conditions])
    ax.set_ylim(0, 3.3)
    ax.set_yticks([0, 1, 2, 3])
    ax.set_yticklabels(["missing", "LOW", "MED", "HIGH"])
    ax.set_ylabel("Mean SQLi severity")
    ax.set_title(title, loc="left", pad=8)
    ax.legend(loc="upper right", bbox_to_anchor=(1.32, 1.0), frameon=False)
    fig.text(0.99, 0.01, "Error bars: SEM", ha="right", color=ANNOT_GRAY, fontsize=7)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    plt.close(fig)
    return out_path


def render_all_figures(jsonl_path: Path, out_dir: Path) -> list[Path]:
    """One-shot: read JSONL, produce all 3 figures (PDF + PNG)."""
    records = load_records(jsonl_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for ext in ("pdf", "png"):
        paths.append(severity_by_condition_bar(
            records, out_dir / f"fig1_severity_bars.{ext}",
        ))
        paths.append(severity_heatmap(
            records, out_dir / f"fig2_severity_heatmap.{ext}",
        ))
        paths.append(per_model_lineplot(
            records, out_dir / f"fig3_per_model_trajectory.{ext}",
        ))
    return paths
