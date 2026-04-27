"""Driver that runs the pentester (Shannon) against a target and emits telemetry.

Real runs only. The runner shells out to the Shannon CLI, parses its
structured report, and writes one JSONL line per run.

Without Shannon installed (and `SHANNON_BIN` exported), this module's CLI
exits with a clear error. There is no mock backend by design — see
`paper/04-mock-vs-real.md`.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Protocol

from .telemetry import (
    Finding,
    HttpEgress,
    RunRecord,
    SCHEMA_VERSION,
    append_jsonl,
    utcnow_iso,
)


class Backend(Protocol):
    name: str

    def execute(self, target: str, repo_path: Path, condition: str) -> dict: ...


class ShannonBackend:
    """Drives the real Shannon CLI.

    `execute` runs `shannon start ...`, then parses the structured report
    Shannon emits in its workflow output directory. The parser is split out
    into `parse_shannon_report` so we can unit-test it on captured fixtures
    without re-running Shannon.
    """
    name = "shannon"

    def __init__(
        self,
        shannon_bin: Path,
        report_dir: Path,
        model: str,
        timeout_seconds: int = 3600,
    ) -> None:
        self.shannon_bin = shannon_bin
        self.report_dir = report_dir
        self.model = model
        self.timeout_seconds = timeout_seconds

    def execute(self, target: str, repo_path: Path, condition: str) -> dict:
        cmd = [
            str(self.shannon_bin),
            "start",
            f"URL=http://{target}",
            f"REPO={repo_path}",
            f"OUTPUT={self.report_dir}",
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=self.timeout_seconds
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"shannon exited {proc.returncode}: {proc.stderr[:500]}"
            )
        report_path = _latest_report(self.report_dir)
        return parse_shannon_report(report_path)


def _latest_report(report_dir: Path) -> Path:
    """Pick the newest `shannon-report-*.md` in `report_dir`."""
    if not report_dir.is_dir():
        raise FileNotFoundError(f"report dir does not exist: {report_dir}")
    candidates = sorted(report_dir.glob("shannon-report-*.md"), key=lambda p: p.stat().st_mtime)
    if not candidates:
        raise FileNotFoundError(f"no shannon-report-*.md found in {report_dir}")
    return candidates[-1]


def parse_shannon_report(path: Path) -> dict:
    """Parse a Shannon Markdown report into our schema.

    NOT YET IMPLEMENTED. The parser must be written against a real Shannon
    report fixture once we pin a Shannon commit (decision D1 in 00-design.md).
    Until then this raises so no run can silently produce empty data.
    """
    raise NotImplementedError(
        f"Shannon report parser is not yet implemented. "
        f"Capture a real report into lab/shannon_runner/tests/fixtures/ and "
        f"implement parsing here. Path attempted: {path}"
    )


def run_once(
    backend: Backend,
    target: str,
    repo_path: Path,
    condition: str,
    payload_id: str | None,
    model: str,
    out_jsonl: Path,
) -> RunRecord:
    started = utcnow_iso()
    t0 = time.monotonic()
    raw = backend.execute(target, repo_path, condition)
    walltime = time.monotonic() - t0
    finished = utcnow_iso()

    record = RunRecord(
        run_id=str(uuid.uuid4()),
        target=target,
        pentester=f"{backend.name}@local",
        model=model,
        condition=condition,
        payload_id=payload_id,
        started_at=started,
        finished_at=finished,
        walltime_seconds=walltime,
        tokens_in=raw.get("tokens_in", 0),
        tokens_out=raw.get("tokens_out", 0),
        findings=[Finding(**f) for f in raw.get("findings", [])],
        egress=[HttpEgress(**e) for e in raw.get("egress", [])],
        schema_version=SCHEMA_VERSION,
    )
    append_jsonl(out_jsonl, record)
    return record


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run a single Shannon execution and log telemetry.")
    p.add_argument("--target", required=True)
    p.add_argument("--repo", required=True, help="Path to the target repo (white-box context)")
    p.add_argument("--condition", default="baseline")
    p.add_argument("--payload-id", default=None)
    p.add_argument("--model", required=True)
    p.add_argument("--shannon-bin", default=os.environ.get("SHANNON_BIN"))
    p.add_argument("--report-dir", default="results/shannon-output")
    p.add_argument("--timeout", type=int, default=3600)
    p.add_argument("--out", required=True, help="JSONL output path")
    args = p.parse_args(argv)

    if not args.shannon_bin:
        print(
            "error: --shannon-bin not provided and SHANNON_BIN is not set. "
            "There is no mock backend; install Shannon and pin its commit "
            "before running.",
            file=sys.stderr,
        )
        return 2

    backend = ShannonBackend(
        shannon_bin=Path(args.shannon_bin),
        report_dir=Path(args.report_dir),
        model=args.model,
        timeout_seconds=args.timeout,
    )
    record = run_once(
        backend=backend,
        target=args.target,
        repo_path=Path(args.repo),
        condition=args.condition,
        payload_id=args.payload_id,
        model=args.model,
        out_jsonl=Path(args.out),
    )
    print(json.dumps({"run_id": record.run_id, "findings": len(record.findings)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
