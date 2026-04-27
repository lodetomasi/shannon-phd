"""Anthropic Messages API client with tool use.

Uses the official `anthropic` SDK directly (Client SDK, not Agent SDK):
we want explicit control over the tool loop because the orchestrator runs
the loop, not the SDK, so ablations and budget enforcement are clean.

No fake mode, no offline mode. If you don't set ANTHROPIC_API_KEY the
constructor raises. Tests that need network skip explicitly.
"""
from __future__ import annotations

import os
from typing import Any, Optional

from .interface import LLMClient, LLMResponse, ToolUse


class AnthropicClient:
    def __init__(
        self,
        model: str,
        input_price_per_mtok: float,
        output_price_per_mtok: float,
        api_key: Optional[str] = None,
    ) -> None:
        # Lazy import so the package can be imported without anthropic installed.
        try:
            import anthropic
        except ImportError as e:
            raise RuntimeError(
                "anthropic SDK is required (pip install anthropic). "
                "If you only need to import the package, you can defer the "
                "AnthropicClient construction."
            ) from e

        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. There is no offline mode."
            )
        self._sdk = anthropic
        self._client = anthropic.Anthropic(api_key=key)
        self.model = model
        self._in_price = input_price_per_mtok
        self._out_price = output_price_per_mtok

    def complete(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
    ) -> LLMResponse:
        response = self._client.messages.create(
            model=self.model,
            system=system,
            messages=messages,
            tools=tools,
            max_tokens=max_tokens,
        )
        return _normalize(response, self._in_price, self._out_price)


def _normalize(
    response: Any, in_price: float, out_price: float
) -> LLMResponse:
    """Convert an Anthropic Message into our provider-neutral shape."""
    text_parts: list[str] = []
    tool_uses: list[ToolUse] = []
    for block in response.content:
        btype = getattr(block, "type", None)
        if btype == "text":
            text_parts.append(block.text)
        elif btype == "tool_use":
            tool_uses.append(
                ToolUse(
                    id=block.id,
                    name=block.name,
                    arguments=dict(block.input or {}),
                )
            )
    usage = getattr(response, "usage", None)
    tokens_in = int(getattr(usage, "input_tokens", 0)) if usage else 0
    tokens_out = int(getattr(usage, "output_tokens", 0)) if usage else 0
    usd_cost = (
        tokens_in / 1_000_000 * in_price + tokens_out / 1_000_000 * out_price
    )
    return LLMResponse(
        text="\n".join(text_parts),
        tool_uses=tuple(tool_uses),
        stop_reason=str(getattr(response, "stop_reason", "")),
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        usd_cost=usd_cost,
        raw={"id": getattr(response, "id", None)},
    )
