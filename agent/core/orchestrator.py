"""ReAct orchestrator with tool dispatch.

Loop:
  1. Send (system, messages, tools) to the LLM.
  2. Apply usage to budget. Check budget — raise if exhausted.
  3. If stop_reason == "tool_use", invoke each tool, append tool_result
     messages, repeat. Otherwise exit.

The orchestrator is intentionally provider-agnostic: it talks to
`LLMClient` (any provider) and `Tool` (any registered tool). No Anthropic-
specific assumptions live here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent.core.budget import Budget
from agent.core.memory import Memory
from agent.llm.interface import LLMClient, LLMResponse
from agent.tools.base import ToolContext, ToolRegistry, ToolResult


@dataclass
class RunOutcome:
    stop_reason: str               # "end_turn" | "max_steps" | "budget_exceeded" | ...
    steps: int
    final_text: str
    findings_count: int
    budget_snapshot: dict
    egress: list[dict] = field(default_factory=list)
    error: str = ""


class Orchestrator:
    def __init__(
        self,
        llm: LLMClient,
        tools: ToolRegistry,
        memory: Memory,
        budget: Budget,
        ctx: ToolContext,
        max_steps: int = 30,
        max_tokens_per_call: int = 4096,
    ) -> None:
        self.llm = llm
        self.tools = tools
        self.memory = memory
        self.budget = budget
        self.ctx = ctx
        self.max_steps = max_steps
        self.max_tokens_per_call = max_tokens_per_call

    def run(self, task: str) -> RunOutcome:
        """Run the ReAct loop until end_turn, max_steps, or budget exhaustion."""
        # Seed the conversation with the task.
        self.memory.append(
            _msg("user", task)  # see helper at bottom
        )
        last_text = ""
        last_stop = ""

        for step in range(self.max_steps):
            try:
                self.budget.check()
            except Exception as e:
                return RunOutcome(
                    stop_reason="budget_exceeded",
                    steps=step,
                    final_text=last_text,
                    findings_count=len(self.memory.findings),
                    budget_snapshot=self.budget.snapshot(),
                    error=str(e),
                )

            response = self._call_llm()
            self.budget.add_call(response.tokens_in, response.tokens_out, response.usd_cost)
            last_text = response.text
            last_stop = response.stop_reason

            # Persist the assistant turn (text + tool_use blocks) verbatim.
            self.memory.append(_assistant_turn(response))

            if response.stop_reason != "tool_use" or not response.tool_uses:
                return self._finalize(last_stop, step + 1, last_text)

            # Dispatch every tool call in this turn, append tool_result messages.
            tool_results: list[dict[str, Any]] = []
            for tu in response.tool_uses:
                result = self._invoke_tool(tu.name, tu.arguments)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tu.id,
                    "content": result.content if result.success else (result.error or ""),
                    "is_error": not result.success,
                })
            self.memory.append(_msg("user", tool_results))

        return self._finalize("max_steps", self.max_steps, last_text)

    # --- internals ----------------------------------------------------------

    def _call_llm(self) -> LLMResponse:
        # We send only the role/content list; the system prompt is passed
        # separately because Anthropic Messages API expects that shape and our
        # protocol mirrors it.
        msgs = [{"role": m.role, "content": m.content} for m in self.memory.messages]
        return self.llm.complete(
            system=self.memory.system_prompt,
            messages=msgs,
            tools=self.tools.schemas(),
            max_tokens=self.max_tokens_per_call,
        )

    def _invoke_tool(self, name: str, args: dict[str, Any]) -> ToolResult:
        try:
            tool = self.tools.get(name)
        except KeyError:
            return ToolResult(False, "", error=f"unknown tool: {name!r}")
        try:
            return tool.invoke(args, self.ctx)
        except Exception as e:  # don't crash the run on tool errors
            return ToolResult(False, "", error=f"tool {name!r} raised: {e!r}")

    def _finalize(self, stop_reason: str, steps: int, last_text: str) -> RunOutcome:
        # Egress log lives on the HttpClient if registered.
        egress: list[dict] = []
        for n in self.tools.names():
            tool = self.tools.get(n)
            getter = getattr(tool, "egress_log", None)
            if callable(getter):
                egress.extend(getter())
        return RunOutcome(
            stop_reason=stop_reason,
            steps=steps,
            final_text=last_text,
            findings_count=len(self.memory.findings),
            budget_snapshot=self.budget.snapshot(),
            egress=egress,
        )


# --- internal helpers (kept private to this module) -------------------------

def _msg(role: str, content):
    """Build a Memory.Message-compatible record. Memory accepts strings;
    for tool_result lists we serialize to a single string for storage and
    rely on the LLM client to re-shape if needed."""
    from agent.core.memory import Message
    if isinstance(content, str):
        return Message(role=role, content=content)
    # We store a JSON-ish flat representation. The orchestrator never reads
    # this back as structured data — only the LLM does, via the wire shape
    # produced by the provider client (which round-trips arbitrary content).
    import json
    return Message(role=role, content=json.dumps(content, default=str))


def _assistant_turn(response: LLMResponse):
    """Persist an assistant turn that may contain text and/or tool_use blocks."""
    from agent.core.memory import Message
    if not response.tool_uses:
        return Message(role="assistant", content=response.text)
    import json
    blocks = []
    if response.text:
        blocks.append({"type": "text", "text": response.text})
    for tu in response.tool_uses:
        blocks.append({"type": "tool_use", "id": tu.id, "name": tu.name, "input": tu.arguments})
    return Message(role="assistant", content=json.dumps(blocks))
