"""Orchestrator plumbing tests.

These tests use a `_ScriptedLLMClient` defined inline — it is NOT a mock of
the real model, it is a test double that replays a pre-defined sequence of
responses to verify the orchestrator's loop behavior. No claim about real
LLM behavior derives from these tests; they only verify that, given an LLM
that says X, the orchestrator does Y.
"""
from __future__ import annotations

from typing import Any

import pytest

from agent.core.budget import Budget, BudgetExceeded
from agent.core.memory import Memory
from agent.core.orchestrator import Orchestrator
from agent.llm.interface import LLMClient, LLMResponse, ToolUse
from agent.tools.base import Tool, ToolContext, ToolRegistry, ToolResult


# ---- test doubles (scoped to this test file) -------------------------------

class _ScriptedLLMClient:
    """Replays a pre-defined sequence of LLMResponse. Test plumbing only."""

    def __init__(self, model: str, script: list[LLMResponse]) -> None:
        self.model = model
        self._script = list(script)
        self.calls: list[dict] = []

    def complete(self, system, messages, tools, max_tokens=4096) -> LLMResponse:
        self.calls.append({"system": system, "messages": list(messages), "tools": list(tools)})
        if not self._script:
            raise RuntimeError("scripted client out of responses — test bug")
        return self._script.pop(0)


class _RecordingTool:
    name = "record"

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def schema(self) -> dict[str, Any]:
        return {
            "description": "test tool",
            "input_schema": {"type": "object", "properties": {"x": {"type": "string"}}},
        }

    def invoke(self, args, ctx) -> ToolResult:
        self.calls.append(args)
        return ToolResult(True, f"recorded:{args.get('x')}")


class _RaisingTool:
    name = "boom"

    def schema(self) -> dict[str, Any]:
        return {"description": "fails", "input_schema": {"type": "object", "properties": {}}}

    def invoke(self, args, ctx) -> ToolResult:
        raise RuntimeError("kaboom")


# ---- helpers ---------------------------------------------------------------

def _resp(text="", tool_uses=(), stop="end_turn", t_in=10, t_out=5, usd=0.001) -> LLMResponse:
    return LLMResponse(
        text=text,
        tool_uses=tuple(tool_uses),
        stop_reason=stop,
        tokens_in=t_in,
        tokens_out=t_out,
        usd_cost=usd,
    )


def _orch(llm, tools, memory=None, budget=None, max_steps=10) -> Orchestrator:
    return Orchestrator(
        llm=llm,
        tools=tools,
        memory=memory or Memory(system_prompt="be useful"),
        budget=budget or Budget(),
        ctx=ToolContext(target_host="t", repo_root="/tmp"),
        max_steps=max_steps,
    )


# ---- tests -----------------------------------------------------------------

def test_single_turn_no_tool_use():
    llm = _ScriptedLLMClient("m", [_resp(text="done")])
    reg = ToolRegistry()
    o = _orch(llm, reg)
    out = o.run("do nothing")
    assert out.stop_reason == "end_turn"
    assert out.steps == 1
    assert out.final_text == "done"
    assert len(llm.calls) == 1


def test_tool_use_dispatches_and_loops():
    rec = _RecordingTool()
    reg = ToolRegistry()
    reg.register(rec)
    llm = _ScriptedLLMClient("m", [
        _resp(stop="tool_use", tool_uses=[ToolUse(id="t1", name="record", arguments={"x": "a"})]),
        _resp(stop="tool_use", tool_uses=[ToolUse(id="t2", name="record", arguments={"x": "b"})]),
        _resp(text="all done", stop="end_turn"),
    ])
    o = _orch(llm, reg)
    out = o.run("record a then b")
    assert out.stop_reason == "end_turn"
    assert out.steps == 3
    assert [c["x"] for c in rec.calls] == ["a", "b"]


def test_multiple_tool_uses_in_one_turn():
    rec = _RecordingTool()
    reg = ToolRegistry()
    reg.register(rec)
    llm = _ScriptedLLMClient("m", [
        _resp(stop="tool_use", tool_uses=[
            ToolUse(id="t1", name="record", arguments={"x": "a"}),
            ToolUse(id="t2", name="record", arguments={"x": "b"}),
        ]),
        _resp(text="ok", stop="end_turn"),
    ])
    o = _orch(llm, reg)
    o.run("two at once")
    assert [c["x"] for c in rec.calls] == ["a", "b"]


def test_unknown_tool_does_not_crash_run():
    reg = ToolRegistry()  # nothing registered
    llm = _ScriptedLLMClient("m", [
        _resp(stop="tool_use", tool_uses=[ToolUse(id="t1", name="ghost", arguments={})]),
        _resp(text="recovered", stop="end_turn"),
    ])
    o = _orch(llm, reg)
    out = o.run("call ghost")
    assert out.stop_reason == "end_turn"
    assert out.steps == 2


def test_tool_exception_does_not_crash_run():
    reg = ToolRegistry()
    reg.register(_RaisingTool())
    llm = _ScriptedLLMClient("m", [
        _resp(stop="tool_use", tool_uses=[ToolUse(id="t1", name="boom", arguments={})]),
        _resp(text="continued", stop="end_turn"),
    ])
    o = _orch(llm, reg)
    out = o.run("trigger boom")
    assert out.stop_reason == "end_turn"


def test_budget_tokens_in_kills_run():
    llm = _ScriptedLLMClient("m", [
        _resp(stop="tool_use", t_in=600, tool_uses=[ToolUse(id="t1", name="record", arguments={})]),
        _resp(text="too late", stop="end_turn", t_in=600),
    ])
    rec = _RecordingTool()
    reg = ToolRegistry()
    reg.register(rec)
    o = _orch(llm, reg, budget=Budget(max_tokens_in=500))
    out = o.run("burn tokens")
    assert out.stop_reason == "budget_exceeded"


def test_max_steps_terminates():
    # LLM keeps asking for tool calls forever.
    rec = _RecordingTool()
    reg = ToolRegistry()
    reg.register(rec)
    script = [
        _resp(stop="tool_use", tool_uses=[ToolUse(id=f"t{i}", name="record", arguments={"x": str(i)})])
        for i in range(20)
    ]
    llm = _ScriptedLLMClient("m", script)
    o = _orch(llm, reg, max_steps=3)
    out = o.run("loop forever")
    assert out.stop_reason == "max_steps"
    assert out.steps == 3


def test_findings_count_propagates_to_outcome():
    from agent.core.memory import Finding
    mem = Memory(system_prompt="x")
    mem.add_finding(Finding("sqli", "/login", "high", "POC", 0.9))
    llm = _ScriptedLLMClient("m", [_resp(text="ok")])
    o = _orch(llm, ToolRegistry(), memory=mem)
    out = o.run("ok")
    assert out.findings_count == 1


def test_egress_log_collected_from_tools_with_getter():
    class _EgressTool:
        name = "fake_http"
        def __init__(self) -> None:
            self.attempts = [{"host": "x", "in_scope": True}]
        def schema(self) -> dict[str, Any]:
            return {"description": "x", "input_schema": {"type": "object", "properties": {}}}
        def invoke(self, args, ctx) -> ToolResult:
            return ToolResult(True, "")
        def egress_log(self) -> list[dict]:
            return self.attempts

    reg = ToolRegistry()
    reg.register(_EgressTool())
    llm = _ScriptedLLMClient("m", [_resp(text="ok")])
    o = _orch(llm, reg)
    out = o.run("noop")
    assert out.egress == [{"host": "x", "in_scope": True}]
