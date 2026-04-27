from __future__ import annotations

from agent.core.memory import Memory
from agent.tools.base import ToolContext
from agent.tools.finding_reporter import FindingReporter


def _ctx() -> ToolContext:
    return ToolContext(target_host="t", repo_root="/tmp")


def _good_args() -> dict:
    return {
        "vuln_class": "sqli",
        "location": "/api/login",
        "severity": "critical",
        "poc": "POST /api/login {\"u\":\"' OR 1=1--\"}",
        "confidence": 0.95,
    }


def test_finding_reporter_records_in_memory():
    m = Memory(system_prompt="x")
    r = FindingReporter(m)
    res = r.invoke(_good_args(), _ctx())
    assert res.success
    assert len(m.findings) == 1
    assert m.findings[0].vuln_class == "sqli"
    assert m.findings[0].confidence == 0.95


def test_finding_reporter_returns_index_for_idempotency():
    m = Memory(system_prompt="x")
    r = FindingReporter(m)
    res1 = r.invoke(_good_args(), _ctx())
    res2 = r.invoke({**_good_args(), "vuln_class": "xss"}, _ctx())
    assert res1.structured["finding_index"] == 0
    assert res2.structured["finding_index"] == 1


def test_finding_reporter_rejects_unknown_severity():
    r = FindingReporter(Memory(system_prompt="x"))
    res = r.invoke({**_good_args(), "severity": "extreme"}, _ctx())
    assert res.success is False
    assert "severity" in res.error


def test_finding_reporter_rejects_confidence_out_of_range():
    r = FindingReporter(Memory(system_prompt="x"))
    res = r.invoke({**_good_args(), "confidence": 1.5}, _ctx())
    assert res.success is False


def test_finding_reporter_rejects_missing_field():
    m = Memory(system_prompt="x")
    r = FindingReporter(m)
    bad = _good_args()
    del bad["location"]
    res = r.invoke(bad, _ctx())
    assert res.success is False
    assert len(m.findings) == 0


def test_finding_reporter_rejects_empty_strings():
    r = FindingReporter(Memory(system_prompt="x"))
    res = r.invoke({**_good_args(), "vuln_class": ""}, _ctx())
    assert res.success is False


def test_finding_reporter_normalizes_severity_case():
    m = Memory(system_prompt="x")
    r = FindingReporter(m)
    res = r.invoke({**_good_args(), "severity": "HIGH"}, _ctx())
    assert res.success
    assert m.findings[0].severity == "high"
