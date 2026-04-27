"""Plot module tests — verify figures render without errors on synthetic data."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from analysis.plots import (
    aggregate_severity,
    load_records,
    per_model_lineplot,
    render_all_figures,
    severity_by_condition_bar,
    severity_heatmap,
)


def _make_synthetic_records(tmp_path: Path) -> Path:
    """Synthesize a minimal records JSONL: 3 models × 3 conditions × 3 runs."""
    records = []
    for model in ["model-a", "model-b", "model-c"]:
        for cond, baseline_sev in [("baseline", 3), ("neutral", 3), ("authority", 2)]:
            for run in range(3):
                records.append({
                    "model": model,
                    "label": model,
                    "condition": cond,
                    "run_index": run,
                    "classification": {
                        "sqli_severity": baseline_sev,
                        "auth_severity": 3,
                        "idor_severity": 2,
                        "xss_severity": 2,
                        "n_findings": 4,
                        "sqli_mentioned": True,
                    },
                })
    p = tmp_path / "synthetic.jsonl"
    with p.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return p


def test_load_records(tmp_path: Path):
    p = _make_synthetic_records(tmp_path)
    records = load_records(p)
    assert len(records) == 27


def test_aggregate_severity_yields_correct_means(tmp_path: Path):
    p = _make_synthetic_records(tmp_path)
    records = load_records(p)
    stats = aggregate_severity(records)
    # 3 models × 3 cond = 9 cells
    assert len(stats) == 9
    for (label, cond), s in stats.items():
        assert s.n == 3
        if cond == "authority":
            assert s.mean == 2.0
        else:
            assert s.mean == 3.0


def test_severity_bar_renders_pdf_and_png(tmp_path: Path):
    p = _make_synthetic_records(tmp_path)
    out_pdf = tmp_path / "bar.pdf"
    out_png = tmp_path / "bar.png"
    severity_by_condition_bar(load_records(p), out_pdf)
    severity_by_condition_bar(load_records(p), out_png)
    assert out_pdf.is_file() and out_pdf.stat().st_size > 1000
    assert out_png.is_file() and out_png.stat().st_size > 1000


def test_heatmap_renders(tmp_path: Path):
    p = _make_synthetic_records(tmp_path)
    out = tmp_path / "heat.pdf"
    severity_heatmap(load_records(p), out)
    assert out.is_file() and out.stat().st_size > 1000


def test_lineplot_renders(tmp_path: Path):
    p = _make_synthetic_records(tmp_path)
    out = tmp_path / "lines.pdf"
    per_model_lineplot(load_records(p), out)
    assert out.is_file() and out.stat().st_size > 1000


def test_render_all_figures_emits_six_files(tmp_path: Path):
    p = _make_synthetic_records(tmp_path)
    out_dir = tmp_path / "figs"
    paths = render_all_figures(p, out_dir)
    assert len(paths) == 6  # 3 figures × 2 formats
    for path in paths:
        assert path.is_file()
        assert path.stat().st_size > 1000


def test_aggregate_handles_empty_classification(tmp_path: Path):
    """A run with no classification field shouldn't crash aggregation."""
    p = tmp_path / "edge.jsonl"
    p.write_text(json.dumps({
        "model": "x", "label": "x", "condition": "baseline",
        # no 'classification' key
    }) + "\n", encoding="utf-8")
    stats = aggregate_severity(load_records(p))
    assert stats == {}
