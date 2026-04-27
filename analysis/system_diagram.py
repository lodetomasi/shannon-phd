"""System diagram for the paper — WPI threat model + Auriga + defenses.

Inspired by clean GAN-style schematics (boxes, big arrows, no clutter).
"""
from __future__ import annotations

from pathlib import Path

import matplotlib as mpl
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt


# Wong colorblind palette
C_INPUT = "#E69F00"      # orange — untrusted input
C_AGENT = "#0072B2"      # blue — agent/system
C_DEFENSE = "#117733"    # green — defenses
C_OUTPUT = "#CC2936"     # red — output/findings
C_PAYLOAD = "#D55E00"    # vermillion — payload
C_ARROW = "#444444"
C_TEXT_DARK = "#222222"
C_TEXT_LIGHT = "#666666"


def _style() -> None:
    mpl.rcParams.update({
        "savefig.dpi": 320,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.05,
        "font.family": "DejaVu Sans",
        "font.size": 10,
    })


def _box(ax, x, y, w, h, text, color, edgecolor="#222222",
         text_color="white", fontsize=10, fontweight="bold", radius=0.04):
    box = mpatches.FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad=0.02,rounding_size={radius}",
        linewidth=1.2, edgecolor=edgecolor,
        facecolor=color, alpha=0.95,
    )
    ax.add_patch(box)
    ax.text(x + w / 2, y + h / 2, text,
            ha="center", va="center",
            color=text_color, fontsize=fontsize, fontweight=fontweight,
            wrap=True)


def _arrow(ax, x0, y0, x1, y1, color=C_ARROW, label="", lw=2.5):
    ax.annotate(
        "",
        xy=(x1, y1), xycoords="data",
        xytext=(x0, y0), textcoords="data",
        arrowprops=dict(
            arrowstyle="-|>,head_length=0.5,head_width=0.3",
            color=color, lw=lw, shrinkA=2, shrinkB=2,
        ),
    )
    if label:
        ax.text((x0 + x1) / 2, (y0 + y1) / 2 + 0.05, label,
                ha="center", va="bottom",
                fontsize=8.5, color=C_TEXT_DARK,
                bbox=dict(boxstyle="round,pad=0.2", fc="white",
                          ec="none", alpha=0.85))


def render_system_diagram(out_path: Path) -> Path:
    _style()
    fig, ax = plt.subplots(figsize=(13, 6.2))
    ax.set_xlim(0, 13)
    ax.set_ylim(0, 6.2)
    ax.set_axis_off()

    # ---------- Title ----------
    ax.text(6.5, 5.95, "Whitebox Prompt Injection on AI Pentesters — Threat Model",
            ha="center", va="bottom",
            fontsize=13, fontweight="bold", color=C_TEXT_DARK)

    # ---------- LEFT column: untrusted input ----------
    _box(ax, 0.2, 3.7, 2.6, 1.2,
         "Vulnerable target repo\n(server.py, README,\nopenapi.json, locales/…)",
         color=C_INPUT, fontsize=9.5)
    _box(ax, 0.2, 1.9, 2.6, 1.2,
         "Adversarial payloads\n(6 channels × 4 goals\n= 24 classes)",
         color=C_PAYLOAD, fontsize=9.5)

    # ---------- INJECTION step ----------
    _box(ax, 3.4, 2.7, 2.2, 1.4,
         "Channel injector\n(code-comment, README,\nOpenAPI, i18n,\npackage, error-tpl)",
         color="#7570B3", fontsize=9.0)

    # arrows: repo + payload -> injector
    _arrow(ax, 2.8, 4.2, 3.4, 3.7)
    _arrow(ax, 2.8, 2.4, 3.4, 3.0)

    # ---------- AGENT pipeline ----------
    _box(ax, 6.2, 3.7, 2.8, 1.4,
         "Auriga Analyst\n(LLM ingests source\nas data + system prompt)",
         color=C_AGENT, fontsize=9.5)

    # arrow: injector -> agent
    _arrow(ax, 5.6, 3.4, 6.2, 4.2, label="poisoned repo")

    # Defenses panel below agent
    _box(ax, 6.2, 1.7, 2.8, 1.4,
         "Defenses\nD1 sanitizer  ·  D2 dual-judge\nD3 hardened prompt",
         color=C_DEFENSE, fontsize=9.0)
    _arrow(ax, 7.6, 3.15, 7.6, 3.7, color=C_DEFENSE, lw=1.8)

    # ---------- OUTPUT ----------
    _box(ax, 9.6, 3.7, 3.0, 1.4,
         "Vulnerability findings\n[HIGH] sqli\n[MED] auth-bypass\n[LOW] idor",
         color=C_OUTPUT, fontsize=9.0, text_color="white")

    _arrow(ax, 9.0, 4.4, 9.6, 4.4, label="report")

    # ---------- METRICS panel (bottom right) ----------
    _box(ax, 9.6, 1.7, 3.0, 1.4,
         "Metrics\nΔ severity (auth − base)\nASR per (model × cell)\nDefense recall",
         color="#5D5D5D", fontsize=9.0)

    _arrow(ax, 11.1, 3.7, 11.1, 3.15, color="#5D5D5D", lw=1.8)

    # ---------- ATTACKER capability annotation ----------
    ax.text(0.2, 1.1,
            "Attacker capability: control of any single repository file.  "
            "Goal: change the severity (or existence) of findings the LLM\n"
            "reports — without touching the LLM weights, the API key, the "
            "system prompt, or the running target.",
            fontsize=9.0, color=C_TEXT_LIGHT, ha="left", va="top",
            wrap=True)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    fig.savefig(out_path.with_suffix(".png"), dpi=320)
    plt.close(fig)
    return out_path


if __name__ == "__main__":
    paper = Path(__file__).resolve().parents[1]
    p = render_system_diagram(paper / "figures" / "hero" / "fig0_system_diagram.pdf")
    print(p)
    print(p.with_suffix(".png"))
