"""Memory: scratchpad + chain-summarization for long contexts.

The orchestrator passes a `Memory` to every reasoning step. It holds:
  - the immutable system prompt
  - the running list of (role, content) messages
  - findings the agent has confirmed so far (typed, structured)
  - a summarization hook that compresses old turns when the context grows

Chain summarization: when total tokens estimate exceeds `summarize_above`,
the oldest non-system messages are replaced with a single "SUMMARY:" turn.
The summarizer callable is injected — for tests we use a deterministic
truncator; in production we plug in an LLM-based summarizer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable


@dataclass(frozen=True)
class Message:
    role: str          # "system" | "user" | "assistant" | "tool"
    content: str
    name: str | None = None    # for tool messages: tool name
    tool_use_id: str | None = None


@dataclass(frozen=True)
class Finding:
    vuln_class: str
    location: str
    severity: str
    poc: str           # textual or shell-replay PoC
    confidence: float  # in [0, 1]


def estimate_tokens(text: str) -> int:
    """Cheap heuristic: ~4 chars per token. Replaced by tiktoken in real runs."""
    return max(1, len(text) // 4)


Summarizer = Callable[[list[Message]], str]


def truncating_summarizer(messages: list[Message]) -> str:
    """Deterministic fallback summarizer used in tests and offline runs."""
    bullets = []
    for m in messages:
        snippet = m.content[:200].replace("\n", " ")
        bullets.append(f"- [{m.role}] {snippet}")
    return "SUMMARY OF EARLIER STEPS:\n" + "\n".join(bullets)


@dataclass
class Memory:
    system_prompt: str
    messages: list[Message] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    summarize_above: int = 80_000   # tokens, configurable
    keep_recent: int = 8            # always keep last N messages verbatim
    summarizer: Summarizer = truncating_summarizer

    def append(self, msg: Message) -> None:
        self.messages.append(msg)
        self._maybe_summarize()

    def extend(self, msgs: Iterable[Message]) -> None:
        for m in msgs:
            self.messages.append(m)
        self._maybe_summarize()

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)

    def total_tokens(self) -> int:
        s = estimate_tokens(self.system_prompt)
        for m in self.messages:
            s += estimate_tokens(m.content)
        return s

    def for_llm(self) -> list[Message]:
        """Return messages in the order to send to the LLM, system first."""
        return [Message(role="system", content=self.system_prompt), *self.messages]

    def _maybe_summarize(self) -> None:
        if self.total_tokens() <= self.summarize_above:
            return
        if len(self.messages) <= self.keep_recent:
            return
        old = self.messages[: -self.keep_recent]
        recent = self.messages[-self.keep_recent :]
        summary_text = self.summarizer(old)
        self.messages = [Message(role="user", content=summary_text), *recent]
