from pathlib import Path

from lab.shannon_runner.telemetry import (
    Finding,
    HttpEgress,
    RunRecord,
    SCHEMA_VERSION,
    append_jsonl,
    read_jsonl,
    utcnow_iso,
)


def _make_record(run_id: str = "r-1") -> RunRecord:
    return RunRecord(
        run_id=run_id,
        target="juice-shop",
        pentester="mock@local",
        model="claude-opus-4-7",
        condition="baseline-temp0",
        payload_id=None,
        started_at=utcnow_iso(),
        finished_at=utcnow_iso(),
        walltime_seconds=12.3,
        tokens_in=1000,
        tokens_out=400,
        findings=[
            Finding("sqli", "/login", "critical", True, True),
            Finding("xss", "/search", "high", True, False),
        ],
        egress=[HttpEgress("GET", "juice-shop", "/", True)],
    )


def test_finding_fingerprint_is_stable_across_severity_changes():
    f1 = Finding("sqli", "/login", "critical", True, True)
    f2 = Finding("sqli", "/login", "low", False, False)
    assert f1.fingerprint() == f2.fingerprint()


def test_record_roundtrips_through_dict():
    r = _make_record()
    r2 = RunRecord.from_dict(r.to_dict())
    assert r == r2


def test_jsonl_append_and_read_roundtrip(tmp_path: Path):
    out = tmp_path / "nested" / "runs.jsonl"
    r1 = _make_record("r-1")
    r2 = _make_record("r-2")

    append_jsonl(out, r1)
    append_jsonl(out, r2)

    records = list(read_jsonl(out))
    assert [r.run_id for r in records] == ["r-1", "r-2"]
    assert records[0].schema_version == SCHEMA_VERSION
    assert records[0].findings[0].fingerprint() == "sqli|/login"


def test_empty_findings_are_preserved(tmp_path: Path):
    out = tmp_path / "runs.jsonl"
    r = _make_record()
    object.__setattr__(r, "findings", [])
    append_jsonl(out, r)
    [back] = list(read_jsonl(out))
    assert back.findings == []
