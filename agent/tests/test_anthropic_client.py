"""Anthropic client tests.

The constructor refuses to operate without a real API key (no offline mode).
The smoke test that hits the real API is gated on `ANTHROPIC_API_KEY` being
set AND `RUN_NETWORK_TESTS=1` (so CI doesn't burn tokens by accident).
"""
from __future__ import annotations

import os

import pytest

from agent.llm.anthropic_client import AnthropicClient


def test_constructor_without_key_raises(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        AnthropicClient(
            model="claude-sonnet-4-6",
            input_price_per_mtok=3.0,
            output_price_per_mtok=15.0,
        )


@pytest.mark.skipif(
    not (os.environ.get("ANTHROPIC_API_KEY") and os.environ.get("RUN_NETWORK_TESTS") == "1"),
    reason="Set ANTHROPIC_API_KEY and RUN_NETWORK_TESTS=1 to enable real API smoke test.",
)
def test_real_api_smoke_no_tools():
    client = AnthropicClient(
        model="claude-haiku-4-5",
        input_price_per_mtok=0.80,
        output_price_per_mtok=4.00,
    )
    res = client.complete(
        system="You are terse. Reply with exactly the word 'pong'.",
        messages=[{"role": "user", "content": "ping"}],
        tools=[],
        max_tokens=16,
    )
    assert res.tokens_in > 0
    assert res.tokens_out > 0
    assert res.usd_cost > 0
    assert res.stop_reason in {"end_turn", "stop_sequence"}
    assert "pong" in res.text.lower()
