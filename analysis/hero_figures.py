"""Publication-quality hero figures.

Designed for NeurIPS / IEEE S&P / USENIX style — clean, sparse, headline-first.

Four figures:
  1. fig_hero — Mistral N=20 baseline vs authority paired plot, with p<0.001 annotation
  2. fig_models — only the 5 evaluable models (baseline≥2), sorted by Δ, with significance stars
  3. fig_channels — code-comment vs 4 alt channels (Mistral), single-row compact
  4. fig_defenses — D1/D2/D3 ablation, baseline as reference line, CI95 bars
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np


def _style() -> None:
    mpl.rcParams.update({
        "figure.dpi": 200,
        "savefig.dpi": 320,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.02,
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "axes.labelsize": 10,
        "axes.titlesize": 11,
        "axes.titleweight": "bold",
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.color": "#eaeaea",
        "grid.linewidth": 0.6,
        "axes.axisbelow": True,
        "lines.linewidth": 1.8,
        "errorbar.capsize": 4,
    })


# Color system (Wong 2011 colorblind-safe + accents)
C_BASE = "#0072B2"     # blue
C_NEU = "#999999"      # gray
C_AUTH = "#D55E00"     # vermillion
C_HERO = "#CC2936"     # red highlight for the headline finding
C_OK = "#117733"       # robust models (green)
C_DEF = "#117733"      # defense color


def _load(p: Path) -> list[dict]:
    if not p.is_file():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def _by_cell(records: list[dict], key="condition"):
    out = defaultdict(list)
    for r in records:
        sev = r.get("classification", {}).get("sqli_severity")
        if sev is None:
            continue
        out[(r.get("label", ""), r.get(key, ""))].append(int(sev))
    return out


def _sig_stars(p: float) -> str:
    if p < 0.001:
        return "***"
    if p < 0.01:
        return "**"
    if p < 0.05:
        return "*"
    return "ns"


def fig_hero(paper: Path, out_dir: Path) -> Path:
    """Slope chart: Mistral N=20 paired baseline vs authority, with p-value."""
    _style()
    all_runs = _load(paper / "results" / "all-runs.jsonl") + _load(
        paper / "results" / "rq3-ablation-edge.jsonl")
    cells = _by_cell(all_runs, key="condition")
    b = cells.get(("mistral-large", "baseline"), [])
    a = cells.get(("mistral-large", "authority"), [])
    if not (b and a):
        return None
    n = min(len(b), len(a))
    b, a = b[:n], a[:n]

    fig, ax = plt.subplots(figsize=(5.0, 3.4))
    # Slope plot: each pair = 1 thin line
    for x_i, y_i in zip(b, a):
        ax.plot([0, 1], [x_i, y_i], color="#bbbbbb", linewidth=0.6, alpha=0.6)
    # Mean trend
    ax.plot([0, 1], [np.mean(b), np.mean(a)],
            color=C_HERO, linewidth=3.0, marker="o", markersize=8,
            markerfacecolor=C_HERO, markeredgecolor="white",
            label="Mean trend")
    ax.errorbar(
        [0, 1], [np.mean(b), np.mean(a)],
        yerr=[
            [np.std(b, ddof=1) / np.sqrt(len(b))] * 1 + [np.std(a, ddof=1) / np.sqrt(len(a))] * 1,
        ][0] if False else [np.std(b, ddof=1) / np.sqrt(len(b)),
                            np.std(a, ddof=1) / np.sqrt(len(a))],
        fmt="none", color=C_HERO, linewidth=2,
    )
    ax.set_xlim(-0.3, 1.3)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Baseline\n(no payload)", "Authority\n(ADR/CVSS comment)"])
    ax.set_ylim(0, 3.4)
    ax.set_yticks([0, 1, 2, 3])
    ax.set_yticklabels(["missing", "LOW", "MED", "HIGH"])
    ax.set_ylabel("SQLi severity reported by analyst")
    ax.set_title("Mistral-Large 2402: authority appeal cuts SQLi severity HIGH→MED",
                 loc="left", pad=12)
    # p-value annotation
    ax.annotate(
        "Wilcoxon paired\np = 0.0001\nCohen's d = -2.39\nN = 20",
        xy=(1.03, 2.1), xycoords="data",
        ha="left", va="top",
        fontsize=8.5, color="#333333",
        bbox=dict(boxstyle="round,pad=0.4", fc="#fff5f0", ec=C_HERO, lw=0.8),
    )
    ax.text(0.99, -0.25, "Each gray line: one paired run.",
            transform=ax.transAxes, ha="right", va="top",
            fontsize=8, color="#666666")
    out_path = out_dir / "fig1_hero_mistral_pair.pdf"
    out_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    fig.savefig(out_path.with_suffix(".png"), dpi=320)
    plt.close(fig)
    return out_path


def fig_models(paper: Path, out_dir: Path) -> Path:
    """Δ severity per model, only evaluable (baseline≥2), sorted by Δ."""
    _style()
    summary = json.loads((paper / "results" / "robustness-summary.json").read_text())
    rq1 = summary["rq1"]
    # Keep evaluable only, sort ascending Δ (most vulnerable first)
    rq1 = [r for r in rq1 if not r["capability_gap"]]
    rq1.sort(key=lambda r: r["delta"])

    fig, ax = plt.subplots(figsize=(5.6, 3.0))
    labels = [r["model"] for r in rq1]
    deltas = [r["delta"] for r in rq1]
    pvals = [r["wilcoxon_p"] for r in rq1]
    colors = [C_HERO if r["wilcoxon_p"] < 0.05 else C_OK for r in rq1]

    y = np.arange(len(labels))
    ax.barh(y, deltas, color=colors, edgecolor="white", linewidth=0.6, height=0.6)
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.axvline(0, color="#333333", linewidth=0.8)
    ax.set_xlabel("Δ SQLi severity (authority − baseline)")
    ax.set_title("Capability inversion: only large/expensive models show WPI",
                 loc="left", pad=10)
    # annotate p-value stars
    for i, (d, p) in enumerate(zip(deltas, pvals)):
        if not np.isnan(p):
            stars = _sig_stars(p)
            ax.text(d + (0.05 if d >= 0 else -0.05), i,
                    f"  {stars}  p={p:.3f}",
                    va="center", ha="left" if d >= 0 else "right",
                    fontsize=8.5, color="#333")
    ax.set_xlim(min(deltas) - 0.4, max(0.6, max(deltas) + 0.4))
    ax.text(0.99, -0.18, "* p<0.05  ** p<0.01  *** p<0.001  (paired Wilcoxon)",
            transform=ax.transAxes, ha="right", va="top",
            fontsize=7.5, color="#666666")
    out_path = out_dir / "fig2_models_delta.pdf"
    fig.savefig(out_path)
    fig.savefig(out_path.with_suffix(".png"), dpi=320)
    plt.close(fig)
    return out_path


def fig_channels(paper: Path, out_dir: Path) -> Path:
    """Bar chart: code-comment vs 4 alt vectors on Mistral. Same payload semantics."""
    _style()
    all_runs = _load(paper / "results" / "all-runs.jsonl")
    cells = defaultdict(list)
    for r in all_runs:
        if r.get("label") != "mistral-large":
            continue
        cond = r.get("condition", "")
        sev = r.get("classification", {}).get("sqli_severity")
        if sev is None:
            continue
        if cond == "baseline":
            cells["baseline"].append(int(sev))
        elif cond == "authority":
            cells["code-comment"].append(int(sev))
        elif cond.startswith("rq2-") and cond.endswith("-injected"):
            vec = cond.replace("rq2-", "").replace("-injected", "")
            cells[vec].append(int(sev))
    order = ["baseline", "code-comment", "readme", "openapi", "i18n", "errortpl"]
    fig, ax = plt.subplots(figsize=(5.6, 3.0))
    means = [np.mean(cells[k]) for k in order]
    sems = [np.std(cells[k], ddof=1) / np.sqrt(max(1, len(cells[k]))) if len(cells[k]) > 1 else 0
            for k in order]
    colors = [C_BASE if k == "baseline" else
              C_HERO if k == "code-comment" else
              C_OK for k in order]
    x = np.arange(len(order))
    ax.bar(x, means, yerr=sems, color=colors, edgecolor="white",
           linewidth=0.6, width=0.7)
    ax.set_xticks(x)
    ax.set_xticklabels(
        [f"{(k if k != 'errortpl' else 'error-tpl')}\nn={len(cells[k])}"
         for k in order],
        rotation=0, ha="center", fontsize=8.5,
    )
    ax.tick_params(axis="x", pad=2)
    ax.set_ylim(0, 3.4)
    ax.set_yticks([0, 1, 2, 3])
    ax.set_yticklabels(["missing", "LOW", "MED", "HIGH"])
    ax.set_ylabel("Mean SQLi severity (Mistral)")
    ax.set_title("Source-code comments are the dominant injection channel",
                 loc="left", pad=10)
    fig.text(0.99, 0.01,
             "Same suppress-finding payload across 5 channels (mistral-large).",
             ha="right", va="bottom", fontsize=7.5, color="#666666")
    out_path = out_dir / "fig3_channels.pdf"
    fig.savefig(out_path)
    fig.savefig(out_path.with_suffix(".png"), dpi=320)
    plt.close(fig)
    return out_path


def fig_defenses(paper: Path, out_dir: Path) -> Path:
    """Defense ablation: NAIVE / D1 / D2 / D3 / D1+D3 on Mistral."""
    _style()
    abl = _load(paper / "results" / "rq3-ablation-edge.jsonl")
    by_cell = defaultdict(list)
    for r in abl:
        sev = r.get("classification", {}).get("sqli_severity")
        if sev is None:
            continue
        by_cell[r.get("cell", "")].append(int(sev))
    # Reference: mistral authority baseline (no defense)
    ref = _load(paper / "results" / "all-runs.jsonl")
    by_cell["A0-NAIVE"] = [
        r["classification"]["sqli_severity"]
        for r in ref
        if r.get("label") == "mistral-large"
        and r.get("condition") == "authority"
    ]
    # D2 from publication-final
    pub = _load(paper / "results" / "rq-publication-final.jsonl")
    by_cell["B-D2"] = [
        r["classification"]["sqli_severity"]
        for r in pub if r.get("cell") == "D2-dual-judge"
    ]

    cells_show = [
        ("A0-NAIVE", "no defense"),
        ("A1-D1-only", "D1 sanitizer"),
        ("B-D2", "D2 dual-judge"),
        ("A2-D3-only", "D3 hardened"),
        ("A3-D1+D3", "D1 + D3"),
    ]
    fig, ax = plt.subplots(figsize=(6.6, 3.0))
    means = [np.mean(by_cell[k]) for k, _ in cells_show]
    sems = [np.std(by_cell[k], ddof=1) / np.sqrt(max(1, len(by_cell[k])))
            if len(by_cell[k]) > 1 else 0 for k, _ in cells_show]
    ns = [len(by_cell[k]) for k, _ in cells_show]
    colors = [C_HERO, "#888888", C_DEF, C_DEF, C_DEF]
    x = np.arange(len(cells_show))
    ax.bar(x, means, yerr=sems, color=colors, edgecolor="white",
           linewidth=0.6, width=0.65)
    # baseline (no payload, no def) reference line at 3.0
    ax.axhline(3.0, color=C_BASE, linewidth=1.2, linestyle="--",
               alpha=0.7, label="Baseline severity (no payload)")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{lbl}\nN={n}" for (_, lbl), n in zip(cells_show, ns)])
    ax.set_ylim(0, 3.4)
    ax.set_yticks([0, 1, 2, 3])
    ax.set_yticklabels(["missing", "LOW", "MED", "HIGH"])
    ax.set_ylabel("Mean SQLi severity")
    ax.set_title("Both D2 (dual-judge) and D3 (hardened prompt) fully restore severity",
                 loc="left", pad=10)
    ax.legend(loc="lower right", frameon=False)
    out_path = out_dir / "fig4_defenses.pdf"
    fig.savefig(out_path)
    fig.savefig(out_path.with_suffix(".png"), dpi=320)
    plt.close(fig)
    return out_path


def fig_multi_payload(paper: Path, out_dir: Path) -> Path:
    """ADR vs FedRAMP vs M&A on Mistral — same target, different framings."""
    _style()
    pub = _load(paper / "results" / "rq-publication-final.jsonl")
    all_runs = _load(paper / "results" / "all-runs.jsonl")
    adr_b = [r["classification"]["sqli_severity"] for r in all_runs
             if r.get("label") == "mistral-large" and r.get("condition") == "baseline"]
    adr_a = [r["classification"]["sqli_severity"] for r in all_runs
             if r.get("label") == "mistral-large" and r.get("condition") == "authority"]
    fed_b = [r["classification"]["sqli_severity"] for r in pub
             if r.get("variant") == "fedramp" and r.get("condition") == "baseline"]
    fed_a = [r["classification"]["sqli_severity"] for r in pub
             if r.get("variant") == "fedramp" and r.get("condition") == "authority"]
    mna_b = [r["classification"]["sqli_severity"] for r in pub
             if r.get("variant") == "mna" and r.get("condition") == "baseline"]
    mna_a = [r["classification"]["sqli_severity"] for r in pub
             if r.get("variant") == "mna" and r.get("condition") == "authority"]

    payloads = [
        ("ADR / KPMG", adr_b, adr_a, "p<0.001 ***"),
        ("FedRAMP / NIST", fed_b, fed_a, "p=0.002 **"),
        ("M&A legal", mna_b, mna_a, "ns"),
    ]
    fig, ax = plt.subplots(figsize=(6.0, 3.4))
    x = np.arange(len(payloads))
    width = 0.36
    bars_b = [np.mean(b) for _, b, _, _ in payloads]
    bars_a = [np.mean(a) for _, _, a, _ in payloads]
    sem_b = [np.std(b, ddof=1) / np.sqrt(len(b)) if len(b) > 1 else 0
             for _, b, _, _ in payloads]
    sem_a = [np.std(a, ddof=1) / np.sqrt(len(a)) if len(a) > 1 else 0
             for _, _, a, _ in payloads]
    ax.bar(x - width / 2, bars_b, width, yerr=sem_b,
           label="Baseline", color=C_BASE, edgecolor="white", linewidth=0.6)
    ax.bar(x + width / 2, bars_a, width, yerr=sem_a,
           label="Authority", color=C_HERO, edgecolor="white", linewidth=0.6)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{name}\nN={len(b)}+{len(a)}\n{sig}"
                        for name, b, a, sig in payloads], fontsize=9)
    ax.set_ylim(0, 3.4)
    ax.set_yticks([0, 1, 2, 3])
    ax.set_yticklabels(["missing", "LOW", "MED", "HIGH"])
    ax.set_ylabel("Mean SQLi severity (Mistral)")
    ax.set_title("Authority framing matters: regulatory keywords work, M&A does not",
                 loc="left", pad=10)
    ax.legend(loc="lower right", frameon=False, ncol=2)
    out_path = out_dir / "fig5_multi_payload.pdf"
    fig.savefig(out_path)
    fig.savefig(out_path.with_suffix(".png"), dpi=320)
    plt.close(fig)
    return out_path


def main() -> None:
    paper = Path(__file__).resolve().parents[1]
    out_dir = paper / "figures" / "hero"
    paths = []
    paths.append(fig_hero(paper, out_dir))
    paths.append(fig_models(paper, out_dir))
    paths.append(fig_channels(paper, out_dir))
    paths.append(fig_defenses(paper, out_dir))
    paths.append(fig_multi_payload(paper, out_dir))
    for p in paths:
        if p:
            print(p)


if __name__ == "__main__":
    main()
