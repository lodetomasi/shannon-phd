"""Bedrock client tests.

Constructor MUST refuse to operate without working AWS credentials.
The smoke test is gated on AWS credentials AND `RUN_NETWORK_TESTS=1`
to avoid accidental cost in CI.
"""
from __future__ import annotations

import os

import pytest


def _aws_profile_set() -> bool:
    return bool(os.environ.get("AWS_PROFILE")) or bool(os.environ.get("AWS_ACCESS_KEY_ID"))


def test_constructor_with_invalid_profile_raises(monkeypatch):
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    from agent.llm.bedrock_client import BedrockAnthropicClient
    with pytest.raises(RuntimeError):
        BedrockAnthropicClient(
            model_id="anthropic.claude-3-haiku-20240307-v1:0",
            region="eu-west-1",
            input_price_per_mtok=0.25,
            output_price_per_mtok=1.25,
            profile_name="this-profile-does-not-exist-xyz",
        )


@pytest.mark.skipif(
    not (_aws_profile_set() and os.environ.get("RUN_NETWORK_TESTS") == "1"),
    reason="Set AWS_PROFILE (or AWS_ACCESS_KEY_ID) and RUN_NETWORK_TESTS=1 to enable.",
)
def test_real_bedrock_smoke_no_tools():
    from agent.llm.bedrock_client import BedrockAnthropicClient
    client = BedrockAnthropicClient(
        model_id="anthropic.claude-3-haiku-20240307-v1:0",
        region="eu-west-1",
        input_price_per_mtok=0.25,
        output_price_per_mtok=1.25,
    )
    res = client.complete(
        system="Reply with the single word 'pong'. No punctuation, no extra words.",
        messages=[{"role": "user", "content": "ping"}],
        tools=[],
        max_tokens=8,
    )
    assert res.tokens_in > 0
    assert res.tokens_out > 0
    assert res.usd_cost > 0
    assert "pong" in res.text.lower()
