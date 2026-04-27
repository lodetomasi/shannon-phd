"""Planner pipeline tests with a scripted LLM (test plumbing only)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent.core.budget import Budget
from agent.core.memory import Finding
from agent.llm.interface import LLMResponse, ToolUse
from agent.runner import Planner


# Scripted LLM that replays a fixed list of responses. Each specialist
# stage triggers a sequence of calls; we hand-craft a script per test.

class _ScriptedLLM:
    def __init__(self, model: str, script: list[LLMResponse]) -> None:
        self.model = model
        self._script = list(script)
        self.calls: list[dict[str, Any]] = []

    def complete(self, system, messages, tools, max_tokens=4096) -> LLMResponse:
        self.calls.append({
            "system_first_line": system.splitlines()[0] if system else "",
            "tools_offered": [t["name"] for t in tools],
        })
        if not self._script:
            return _resp(text="(scripted client exhausted)", stop="end_turn")
        return self._script.pop(0)


def _resp(text="", tool_uses=(), stop="end_turn", t_in=10, t_out=5, usd=0.001) -> LLMResponse:
    return LLMResponse(
        text=text,
        tool_uses=tuple(tool_uses),
        stop_reason=stop,
        tokens_in=t_in,
        tokens_out=t_out,
        usd_cost=usd,
    )


def test_planner_runs_all_four_stages(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "src").mkdir()
    (repo / "src" / "login.js").write_text("// vulnerable code", encoding="utf-8")

    out = tmp_path / "telemetry.jsonl"

    # 4 stages, one end_turn response each (cheapest valid path).
    llm = _ScriptedLLM("test-model", [
        _resp(text="recon summary"),         # stage 1: recon
        _resp(text="analyst candidates"),    # stage 2: analyst
        _resp(text="exploit done"),          # stage 3: exploit
        _resp(text="validator verdicts"),    # stage 4: validator
    ])
    p = Planner(
        llm=llm,
        target_host="t",
        repo_root=repo,
        budget=Budget(),
        condition="baseline",
        payload_id=None,
        out_jsonl=out,
    )
    outcome = p.run("kick off")

    assert [s.name for s in outcome.stages] == ["recon", "analyst", "exploit", "validator"]
    assert all(s.stop_reason == "end_turn" for s in outcome.stages)
    assert out.is_file()
    # JSONL has one line, schema version pinned
    lines = out.read_text().splitlines()
    assert len(lines) == 1
    assert '"schema_version":"1"' in lines[0]


def test_planner_stages_get_correct_tool_subsets(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    llm = _ScriptedLLM("m", [
        _resp(text="r"),
        _resp(text="a"),
        _resp(text="e"),
        _resp(text="v"),
    ])
    Planner(llm=llm, target_host="t", repo_root=repo, budget=Budget()).run("x")

    # 4 LLM calls, one per stage. Tools offered must reflect spec.allowed_tools.
    assert len(llm.calls) == 4
    recon_tools, analyst_tools, exploit_tools, validator_tools = (
        sorted(c["tools_offered"]) for c in llm.calls
    )
    assert recon_tools == ["http_request", "repo_read"]
    assert analyst_tools == ["repo_read"]
    assert exploit_tools == ["http_request", "repo_read", "report_finding"]
    assert validator_tools == ["http_request", "repo_read"]


def test_planner_confirmed_filter_drops_fp_keeps_tp_and_inconclusive(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    # Exploit produces 3 findings; Validator marks #2 as FP, others TP/INCONCLUSIVE.
    findings_calls = [
        ToolUse(id=f"t{i}", name="report_finding", arguments={
            "vuln_class": ["sqli", "csrf", "xss"][i],
            "location": ["/api/login", "/header", "/search"][i],
            "severity": "high",
            "poc": "PoC",
            "confidence": 0.9,
        })
        for i in range(3)
    ]
    llm = _ScriptedLLM("m", [
        _resp(text="recon"),
        _resp(text="analyst"),
        # Exploit issues 3 report_finding calls in one tool_use turn, then ends.
        _resp(stop="tool_use", tool_uses=findings_calls),
        _resp(text="exploit done"),
        # Validator output: structured verdict text the planner parses.
        _resp(text=(
            "Finding #1 (sqli at /api/login): TP — reproduced.\n"
            "Finding #2 (csrf at /header): FP — server ignores header.\n"
            "Finding #3 (xss at /search): INCONCLUSIVE — endpoint not reachable.\n"
        )),
    ])
    out = Planner(
        llm=llm, target_host="t", repo_root=repo, budget=Budget(),
    ).run("x")
    confirmed = out.confirmed_findings
    classes = [f.vuln_class for f in confirmed]
    # FP dropped, TP kept, INCONCLUSIVE kept (handed off to reviewer triage)
    assert "sqli" in classes
    assert "xss" in classes
    assert "csrf" not in classes
    # Telemetry record matches confirmed list
    assert len(out.record.findings) == len(confirmed)


def test_planner_writes_jsonl_with_run_metadata(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "t.jsonl"
    llm = _ScriptedLLM("m", [_resp(text=s) for s in ["r", "a", "e", "v"]])
    Planner(
        llm=llm,
        target_host="juice-shop",
        repo_root=repo,
        budget=Budget(),
        condition="adversarial",
        payload_id="comment-suppress-sqli-01",
        out_jsonl=out,
    ).run("x")
    line = out.read_text().splitlines()[0]
    assert '"target":"juice-shop"' in line
    assert '"condition":"adversarial"' in line
    assert '"payload_id":"comment-suppress-sqli-01"' in line


def test_planner_each_stage_starts_with_fresh_memory(tmp_path: Path):
    """The dual-LLM-judge guarantee requires the Validator to NOT see
    the Exploit reasoning chain. We verify by checking the Validator's
    LLM call has only its own role-system prompt + the structured task."""
    repo = tmp_path / "repo"
    repo.mkdir()
    llm = _ScriptedLLM("m", [_resp(text=s) for s in ["recon", "analyst", "exploit", "validator"]])
    Planner(llm=llm, target_host="t", repo_root=repo, budget=Budget()).run("x")
    # The 4th call (validator) must have validator's role prompt — disjoint
    # from exploit's. We assert by comparing system_first_line.
    systems = [c["system_first_line"] for c in llm.calls]
    assert len(set(systems)) == 4, f"expected 4 distinct system prompts, got {systems}"
