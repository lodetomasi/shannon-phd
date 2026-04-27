"""Run telemetry schema and JSONL persistence.

A `RunRecord` is the unit of measurement for the paper:
one execution of the pentester against one target, in one condition,
optionally with one injected payload.
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "1"


@dataclass(frozen=True)
class Finding:
    """A single vulnerability reported by the pentester."""
    vuln_class: str          # e.g. "sqli", "xss", "ssrf", "auth-bypass"
    location: str            # endpoint or file:line
    severity: str            # "low" | "medium" | "high" | "critical"
    poc_present: bool        # did the pentester produce a runnable PoC?
    poc_validated: bool      # did the PoC succeed when re-executed?

    def fingerprint(self) -> str:
        """Stable identity used for inter-run set comparison."""
        return f"{self.vuln_class}|{self.location}"


@dataclass(frozen=True)
class HttpEgress:
    """A single outbound HTTP request observed during the run."""
    method: str
    host: str
    path: str
    in_scope: bool


@dataclass
class RunRecord:
    run_id: str
    target: str               # e.g. "juice-shop"
    pentester: str            # e.g. "shannon-lite@<commit>"
    model: str                # e.g. "claude-opus-4-7"
    condition: str            # free-form label, e.g. "baseline-temp0"
    payload_id: str | None    # None for benign baseline
    started_at: str           # ISO-8601 UTC
    finished_at: str          # ISO-8601 UTC
    walltime_seconds: float
    tokens_in: int
    tokens_out: int
    findings: list[Finding] = field(default_factory=list)
    egress: list[HttpEgress] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RunRecord":
        findings = [Finding(**f) for f in d.get("findings", [])]
        egress = [HttpEgress(**e) for e in d.get("egress", [])]
        kwargs = {k: v for k, v in d.items() if k not in ("findings", "egress")}
        return cls(findings=findings, egress=egress, **kwargs)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def append_jsonl(path: Path, record: RunRecord) -> None:
    """Append a single RunRecord as one JSON line. Creates parents if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record.to_dict(), separators=(",", ":"), sort_keys=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def read_jsonl(path: Path) -> Iterable[RunRecord]:
    """Read RunRecord entries lazily from a JSONL file."""
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            yield RunRecord.from_dict(json.loads(raw))
