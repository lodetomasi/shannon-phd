"""Specialist agent: an orchestrator pre-configured for one role.

A `Specialist` bundles:
  - a name
  - the system prompt (Markdown file under agent/prompts/)
  - the subset of tool names this agent is allowed to use
  - the model id
  - the per-run step cap

It does NOT own the LLM client or the tool registry — those are injected
at run time. This keeps Specialist instances cheap and lets us swap models
per ablation (RQ2: cross-family robustness).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from agent.core.budget import Budget
from agent.core.memory import Memory
from agent.core.orchestrator import Orchestrator, RunOutcome
from agent.llm.interface import LLMClient
from agent.tools.base import ToolContext, ToolRegistry


PROMPTS_DIR = Path(__file__).resolve().parents[1] / "prompts"


@dataclass(frozen=True)
class Specialist:
    name: str
    prompt_file: str           # filename inside agent/prompts/
    allowed_tools: tuple[str, ...]
    max_steps: int = 30

    def system_prompt(self) -> str:
        path = PROMPTS_DIR / self.prompt_file
        if not path.is_file():
            raise FileNotFoundError(f"prompt file missing: {path}")
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            raise ValueError(f"prompt file is empty: {path}")
        return text

    def filter_tools(self, registry: ToolRegistry) -> ToolRegistry:
        """Return a new registry containing only this specialist's allowed tools."""
        sub = ToolRegistry()
        for name in self.allowed_tools:
            sub.register(registry.get(name))
        return sub

    def run(
        self,
        task: str,
        llm: LLMClient,
        registry: ToolRegistry,
        ctx: ToolContext,
        budget: Budget,
        memory: Memory | None = None,
    ) -> tuple[RunOutcome, Memory]:
        """Execute the specialist on `task`. Returns (outcome, memory)."""
        mem = memory or Memory(system_prompt=self.system_prompt())
        sub_registry = self.filter_tools(registry)
        orch = Orchestrator(
            llm=llm,
            tools=sub_registry,
            memory=mem,
            budget=budget,
            ctx=ctx,
            max_steps=self.max_steps,
        )
        outcome = orch.run(task)
        return outcome, mem


# --- Canonical specialists used in the paper -------------------------------

RECON = Specialist(
    name="recon",
    prompt_file="recon.md",
    allowed_tools=("repo_read", "http_request"),
    max_steps=20,
)

ANALYST = Specialist(
    name="analyst",
    prompt_file="analyst.md",
    allowed_tools=("repo_read",),
    max_steps=30,
)

EXPLOIT = Specialist(
    name="exploit",
    prompt_file="exploit.md",
    allowed_tools=("repo_read", "http_request", "report_finding"),
    max_steps=40,
)

VALIDATOR = Specialist(
    name="validator",
    prompt_file="validator.md",
    allowed_tools=("repo_read", "http_request"),
    max_steps=25,
)


ALL_SPECIALISTS: Sequence[Specialist] = (RECON, ANALYST, EXPLOIT, VALIDATOR)


# --- Text-only Analyst variant for cross-family ablation -------------------
#
# Some Bedrock models (Mistral 7B, OpenAI GPT-OSS, Qwen, Gemma) do NOT
# support tool use via Converse. They can still play the Analyst role:
# given a code snippet they emit a list of suspicious locations as text.
#
# The orchestrator works in zero-tool mode: the LLM produces final text on
# the first turn (no tool_use blocks). This is the "Analyst-only"
# experimental cell — we measure WPI on the *static analysis* sub-task in
# isolation, separate from the full Recon→Exploit pipeline.

ANALYST_ONLY = Specialist(
    name="analyst-only",
    prompt_file="analyst.md",
    allowed_tools=(),       # no tools — pure text-in / text-out
    max_steps=1,            # single LLM call
)


# Naive variant of the Analyst: a code reviewer system prompt with NO
# anti-WPI defense baked in. Used as control to isolate the effect of
# the source-as-data hardening (D3). RQ1 vs RQ3 separation.
ANALYST_ONLY_NAIVE = Specialist(
    name="analyst-only-naive",
    prompt_file="analyst_naive.md",
    allowed_tools=(),
    max_steps=1,
)
