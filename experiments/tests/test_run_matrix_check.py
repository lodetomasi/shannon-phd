from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.run_matrix import load_matrix, main


def _matrix_file(tmp_path: Path) -> Path:
    p = tmp_path / "matrix.json"
    p.write_text(json.dumps({
        "cells": [
            {"target": "juice-shop", "model_id": "claude-sonnet-4-6",
             "condition": "baseline", "n_runs": 5},
            {"target": "juice-shop", "model_id": "claude-sonnet-4-6",
             "condition": "adversarial", "payload_id": "comment-suppress-sqli-01",
             "n_runs": 5},
        ]
    }))
    return p


def _profiles_file(tmp_path: Path) -> Path:
    p = tmp_path / "profiles.json"
    p.write_text(json.dumps({
        "auriga-baseline": {"tokens_in": 100_000, "tokens_out": 12_000},
        "auriga-adversarial": {"tokens_in": 110_000, "tokens_out": 14_000},
    }))
    return p


def test_load_matrix_parses_cells(tmp_path: Path):
    cells = load_matrix(_matrix_file(tmp_path))
    assert len(cells) == 2
    assert cells[0].condition == "baseline"
    assert cells[1].payload_id == "comment-suppress-sqli-01"


def test_check_only_within_budget(tmp_path: Path, capsys):
    rc = main([
        "--matrix", str(_matrix_file(tmp_path)),
        "--profiles", str(_profiles_file(tmp_path)),
        "--budget-usd", "100",
        "--check-only",
        "--out", str(tmp_path / "ignored.jsonl"),
    ])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["n_cells"] == 2
    assert summary["n_runs_total"] == 10
    assert summary["feasible"] is True


def test_check_only_over_budget(tmp_path: Path, capsys):
    rc = main([
        "--matrix", str(_matrix_file(tmp_path)),
        "--profiles", str(_profiles_file(tmp_path)),
        "--budget-usd", "0.01",
        "--check-only",
        "--out", str(tmp_path / "ignored.jsonl"),
    ])
    assert rc == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary["feasible"] is False
    assert summary["scale_n_to"] < 10


def test_full_run_blocks_without_credentials(tmp_path: Path, capsys):
    """When not --check-only, the matrix runner refuses to execute without
    the lab env. We want this assertion in tests so accidents fail loud."""
    rc = main([
        "--matrix", str(_matrix_file(tmp_path)),
        "--profiles", str(_profiles_file(tmp_path)),
        "--budget-usd", "100",
        "--out", str(tmp_path / "out.jsonl"),
    ])
    err = capsys.readouterr().err
    assert "ANTHROPIC_API_KEY" in err
    assert rc == 0  # we exit cleanly with a message, not a crash
