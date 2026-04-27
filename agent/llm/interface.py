"""Provider-agnostic LLM client interface.

The orchestrator only ever talks to an `LLMClient`. Anthropic, OpenAI, and
OpenRouter all conform to this protocol. Swapping providers is one
constructor argument — useful for the cross-family robustness section
(RQ2: is WPI model-family-dependent?).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ToolUse:
    """LLM-issued tool invocation."""
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class LLMResponse:
    """Normalized response shape across providers."""
    text: str                       # final assistant text (concatenated TextBlocks)
    tool_uses: tuple[ToolUse, ...]  # tool_use blocks the model produced
    stop_reason: str                # "end_turn" | "tool_use" | "max_tokens" | ...
    tokens_in: int
    tokens_out: int
    usd_cost: float
    raw: dict[str, Any] = field(default_factory=dict)  # provider-specific blob


class LLMClient(Protocol):
    """All clients must expose this single method."""
    model: str

    def complete(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
    ) -> LLMResponse: ...
