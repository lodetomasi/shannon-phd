from __future__ import annotations

import os

import pytest


def _aws_set() -> bool:
    return bool(os.environ.get("AWS_PROFILE")) or bool(os.environ.get("AWS_ACCESS_KEY_ID"))


def test_constructor_requires_working_credentials(monkeypatch):
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    from agent.llm.bedrock_converse_client import BedrockConverseClient
    with pytest.raises(RuntimeError):
        BedrockConverseClient(
            model_id="mistral.mistral-7b-instruct-v0:2",
            region="eu-west-1",
            input_price_per_mtok=0.15,
            output_price_per_mtok=0.20,
            profile_name="this-profile-does-not-exist-xyz",
        )


@pytest.mark.parametrize("model_id,in_price,out_price,supports_tool_use,supports_system", [
    ("anthropic.claude-3-haiku-20240307-v1:0", 0.25, 1.25, True, True),
    ("mistral.mistral-7b-instruct-v0:2", 0.15, 0.20, False, False),
    ("openai.gpt-oss-20b-1:0", 0.07, 0.30, False, True),
    ("qwen.qwen3-32b-v1:0", 0.20, 0.60, False, True),
])
@pytest.mark.skipif(
    not (_aws_set() and os.environ.get("RUN_NETWORK_TESTS") == "1"),
    reason="Set AWS_PROFILE and RUN_NETWORK_TESTS=1 to enable.",
)
def test_real_converse_smoke(model_id, in_price, out_price, supports_tool_use, supports_system):
    """One ping per model. Total cost < $0.001 across all parametrizations."""
    from agent.llm.bedrock_converse_client import BedrockConverseClient
    client = BedrockConverseClient(
        model_id=model_id,
        region="eu-west-1",
        input_price_per_mtok=in_price,
        output_price_per_mtok=out_price,
        supports_tool_use=supports_tool_use,
        supports_system_prompt=supports_system,
    )
    res = client.complete(
        system="Reply with the single word 'pong'.",
        messages=[{"role": "user", "content": "ping"}],
        tools=[],
        max_tokens=64,
    )
    # Connectivity invariant: prompt was sent, response arrived, billing accrued.
    assert res.tokens_in > 0, f"no input tokens billed for {model_id}"
    assert res.tokens_out > 0, f"no output tokens for {model_id}"
    assert res.usd_cost > 0, f"no usd cost for {model_id}"
    # Compliance check: pong should appear in text. Some smaller models burn
    # tokens on internal reasoning before emitting; tolerate that.
    if res.text.strip():
        assert "pong" in res.text.lower(), (
            f"{model_id} responded with non-pong text: {res.text!r}"
        )
