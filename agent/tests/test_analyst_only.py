"""Analyst-only specialist tests.

Goal: a Specialist with zero tools that runs a single LLM call must
exit cleanly with the LLM's text in `final_text` and never invoke a tool.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent.agents.base import ANALYST_ONLY
from agent.core.budget import Budget
from agent.core.memory import Memory
from agent.llm.interface import LLMResponse
from agent.tools.base import ToolContext, ToolRegistry


class _ScriptedLLM:
    def __init__(self, model: str, response: LLMResponse) -> None:
        self.model = model
        self._response = response
        self.calls: list[dict[str, Any]] = []

    def complete(self, system, messages, tools, max_tokens=4096) -> LLMResponse:
        self.calls.append({
            "system": system,
            "messages": list(messages),
            "tools": list(tools),
            "max_tokens": max_tokens,
        })
        return self._response


def test_analyst_only_has_zero_tools():
    assert ANALYST_ONLY.allowed_tools == ()


def test_analyst_only_max_steps_is_one():
    assert ANALYST_ONLY.max_steps == 1


def test_analyst_only_offers_no_tools_to_llm(tmp_path: Path):
    repo = tmp_path
    (repo / "src").mkdir()
    (repo / "src" / "auth.js").write_text(
        "function login(u,p) { return db.exec('SELECT * FROM u WHERE u=' + u); }",
        encoding="utf-8",
    )
    llm = _ScriptedLLM("m", LLMResponse(
        text="1. [HIGH] src/auth.js:1 — direct concat into SQL",
        tool_uses=(),
        stop_reason="end_turn",
        tokens_in=120,
        tokens_out=20,
        usd_cost=0.0001,
    ))

    full = ToolRegistry()  # populated registry — but Analyst-only filters all out
    outcome, _ = ANALYST_ONLY.run(
        task="Analyze src/auth.js for vulnerabilities.",
        llm=llm,
        registry=full,
        ctx=ToolContext(target_host="t", repo_root=str(repo)),
        budget=Budget(),
    )

    assert outcome.stop_reason == "end_turn"
    assert outcome.steps == 1
    assert "src/auth.js" in outcome.final_text
    # verify the LLM was offered ZERO tools (key invariant for text-only models)
    assert llm.calls[0]["tools"] == []


def test_analyst_only_terminates_at_max_steps_if_llm_returns_tool_use(tmp_path: Path):
    """Even if a misconfigured LLM returns tool_use, max_steps=1 stops the loop."""
    from agent.llm.interface import ToolUse
    repo = tmp_path
    llm = _ScriptedLLM("m", LLMResponse(
        text="",
        tool_uses=(ToolUse(id="x", name="ghost", arguments={}),),
        stop_reason="tool_use",
        tokens_in=10, tokens_out=5, usd_cost=0.001,
    ))
    outcome, _ = ANALYST_ONLY.run(
        task="x",
        llm=llm,
        registry=ToolRegistry(),
        ctx=ToolContext(target_host="t", repo_root=str(repo)),
        budget=Budget(),
    )
    # The orchestrator handled the tool_use turn (no tools registered → unknown tool),
    # then max_steps=1 forced termination.
    assert outcome.stop_reason == "max_steps"
