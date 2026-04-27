"""Runner tests.

These tests exercise the runner *infrastructure* (CLI plumbing, error paths,
parser contract). They do NOT substitute Shannon with a fake backend — the
mock backend has been removed (see `paper/04-mock-vs-real.md`). Tests that
need a real Shannon binary skip unless `SHANNON_BIN` is set in the env.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from lab.shannon_runner.runner import (
    ShannonBackend,
    _latest_report,
    main,
    parse_shannon_report,
)


def test_parse_shannon_report_not_implemented_yet(tmp_path: Path):
    """Until we capture a real Shannon report fixture and implement parsing,
    the parser must fail loudly — never silently return empty data."""
    fake_path = tmp_path / "shannon-report-foo.md"
    fake_path.write_text("# placeholder", encoding="utf-8")
    with pytest.raises(NotImplementedError):
        parse_shannon_report(fake_path)


def test_latest_report_picks_newest(tmp_path: Path):
    older = tmp_path / "shannon-report-1.md"
    newer = tmp_path / "shannon-report-2.md"
    older.write_text("a", encoding="utf-8")
    newer.write_text("b", encoding="utf-8")
    # ensure mtime ordering
    os.utime(older, (1, 1))
    os.utime(newer, (2, 2))
    assert _latest_report(tmp_path) == newer


def test_latest_report_missing_dir_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        _latest_report(tmp_path / "does-not-exist")


def test_latest_report_no_files_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        _latest_report(tmp_path)


def test_main_without_shannon_bin_returns_error(monkeypatch, tmp_path: Path, capsys):
    monkeypatch.delenv("SHANNON_BIN", raising=False)
    rc = main([
        "--target", "juice-shop",
        "--repo", str(tmp_path),
        "--model", "claude-opus-4-7",
        "--out", str(tmp_path / "out.jsonl"),
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "SHANNON_BIN" in err
    assert "no mock backend" in err


@pytest.mark.skipif(
    not os.environ.get("SHANNON_BIN"),
    reason="Requires a real Shannon installation (set SHANNON_BIN to enable).",
)
def test_real_shannon_smoke(tmp_path: Path):
    """End-to-end run with a real Shannon binary. Skipped in CI without it."""
    backend = ShannonBackend(
        shannon_bin=Path(os.environ["SHANNON_BIN"]),
        report_dir=tmp_path / "reports",
        model="claude-opus-4-7",
    )
    # This will only succeed once parse_shannon_report is implemented and a
    # real target is reachable. Today it documents the integration boundary.
    with pytest.raises(NotImplementedError):
        backend.execute("example.com", tmp_path, "baseline")
