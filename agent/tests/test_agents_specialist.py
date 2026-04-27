from __future__ import annotations

from typing import Any

import pytest

from agent.agents.base import (
    ALL_SPECIALISTS,
    ANALYST,
    EXPLOIT,
    RECON,
    Specialist,
    VALIDATOR,
)
from agent.core.budget import Budget
from agent.core.memory import Memory
from agent.llm.interface import LLMResponse, ToolUse
from agent.tools.base import ToolContext, ToolRegistry, ToolResult
from agent.tools.finding_reporter import FindingReporter
from agent.tools.http_client import HttpClient, HttpResponse
from agent.tools.repo_reader import RepoReader


# --- prompt + structure validation -----------------------------------------

@pytest.mark.parametrize("spec", ALL_SPECIALISTS, ids=lambda s: s.name)
def test_each_specialist_has_a_loadable_prompt(spec: Specialist):
    text = spec.system_prompt()
    assert len(text) > 200, f"{spec.name} prompt is suspiciously short"
    # Each prompt MUST teach the WPI defense — source-code is data.
    lower = text.lower()
    assert "data, not instructions" in lower or "untrusted" in lower, (
        f"{spec.name} prompt is missing the source-code-as-data rule"
    )


def test_specialist_names_unique():
    names = [s.name for s in ALL_SPECIALISTS]
    assert len(names) == len(set(names))


def test_only_exploit_can_call_report_finding():
    for s in ALL_SPECIALISTS:
        if s.name == "exploit":
            assert "report_finding" in s.allowed_tools
        else:
            assert "report_finding" not in s.allowed_tools, (
                f"{s.name} must not be able to report findings"
            )


def test_analyst_is_read_only_no_http():
    assert "http_request" not in ANALYST.allowed_tools
    assert "repo_read" in ANALYST.allowed_tools


def test_validator_has_both_read_and_http():
    # D2 dual-LLM judge needs to re-verify both code AND runtime
    assert "repo_read" in VALIDATOR.allowed_tools
    assert "http_request" in VALIDATOR.allowed_tools
    assert "report_finding" not in VALIDATOR.allowed_tools


# --- filter_tools behavior --------------------------------------------------

def test_filter_tools_returns_subset():
    full = ToolRegistry()
    full.register(RepoReader())
    full.register(HttpClient(transport=lambda *a, **kw: HttpResponse(200, {}, "")))
    full.register(FindingReporter(Memory(system_prompt="x")))

    sub = ANALYST.filter_tools(full)
    assert sub.names() == ["repo_read"]


def test_filter_tools_rejects_unknown_allowed_name():
    bogus = Specialist(
        name="bogus",
        prompt_file="recon.md",
        allowed_tools=("does_not_exist",),
    )
    with pytest.raises(KeyError):
        bogus.filter_tools(ToolRegistry())


# --- end-to-end with a scripted LLM client ---------------------------------

class _ScriptedLLMClient:
    def __init__(self, model: str, script: list[LLMResponse]) -> None:
        self.model = model
        self._script = list(script)
        self.calls: list[dict[str, Any]] = []

    def complete(self, system, messages, tools, max_tokens=4096) -> LLMResponse:
        self.calls.append({"system": system, "tools_offered": [t["name"] for t in tools]})
        return self._script.pop(0)


def _resp(text="", tool_uses=(), stop="end_turn") -> LLMResponse:
    return LLMResponse(
        text=text,
        tool_uses=tuple(tool_uses),
        stop_reason=stop,
        tokens_in=10,
        tokens_out=5,
        usd_cost=0.001,
    )


def test_exploit_specialist_can_actually_record_a_finding(tmp_path):
    repo = tmp_path
    (repo / "src").mkdir()
    (repo / "src" / "login.js").write_text("// vulnerable code", encoding="utf-8")

    mem = Memory(system_prompt=EXPLOIT.system_prompt())

    full = ToolRegistry()
    full.register(RepoReader())
    full.register(HttpClient(transport=lambda *a, **kw: HttpResponse(200, {}, "exploited")))
    full.register(FindingReporter(mem))

    llm = _ScriptedLLMClient("m", [
        _resp(stop="tool_use", tool_uses=[
            ToolUse(id="t1", name="report_finding", arguments={
                "vuln_class": "sqli",
                "location": "/api/login",
                "severity": "critical",
                "poc": "POST /api/login {\"u\":\"' OR 1=1--\"}",
                "confidence": 0.95,
            }),
        ]),
        _resp(text="reported 1 finding", stop="end_turn"),
    ])

    outcome, mem_out = EXPLOIT.run(
        task="exploit /api/login",
        llm=llm,
        registry=full,
        ctx=ToolContext(target_host="t", repo_root=str(repo)),
        budget=Budget(),
        memory=mem,
    )
    assert outcome.stop_reason == "end_turn"
    assert outcome.findings_count == 1
    assert mem_out.findings[0].vuln_class == "sqli"


def test_analyst_cannot_call_report_finding_via_orchestrator(tmp_path):
    """Even if the LLM tries to call report_finding, the analyst's tool subset
    refuses it because the tool is not in the analyst's filtered registry."""
    repo = tmp_path
    mem = Memory(system_prompt=ANALYST.system_prompt())

    full = ToolRegistry()
    full.register(RepoReader())
    full.register(FindingReporter(mem))

    llm = _ScriptedLLMClient("m", [
        _resp(stop="tool_use", tool_uses=[
            ToolUse(id="t1", name="report_finding", arguments={
                "vuln_class": "sqli", "location": "/x", "severity": "high",
                "poc": "x", "confidence": 0.9,
            }),
        ]),
        _resp(text="recovered", stop="end_turn"),
    ])

    outcome, mem_out = ANALYST.run(
        task="analyze",
        llm=llm,
        registry=full,
        ctx=ToolContext(target_host="t", repo_root=str(repo)),
        budget=Budget(),
        memory=mem,
    )
    # The orchestrator returned `unknown tool: report_finding`; no finding registered.
    assert outcome.findings_count == 0
    assert len(mem_out.findings) == 0
    # And the LLM was offered ONLY repo_read.
    assert llm.calls[0]["tools_offered"] == ["repo_read"]
