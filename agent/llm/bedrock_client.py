"""AWS Bedrock client — Anthropic Claude models hosted on Bedrock.

Same `LLMClient` Protocol as `agent/llm/anthropic_client.py`. Uses boto3
directly (no anthropic SDK) because Bedrock has its own envelope:

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": ...,
        "system": ...,
        "messages": [...],
        "tools": [...]
    }

Tool-use response shape is identical to the Anthropic Messages API:
content blocks of type "text" or "tool_use".

No fake mode. Constructor refuses to operate without working AWS
credentials reachable from the environment / profile.
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

from .interface import LLMClient, LLMResponse, ToolUse


class BedrockAnthropicClient:
    """Drives Anthropic Claude models via Bedrock Runtime."""

    def __init__(
        self,
        model_id: str,
        region: str,
        input_price_per_mtok: float,
        output_price_per_mtok: float,
        profile_name: Optional[str] = None,
    ) -> None:
        try:
            import boto3
            from botocore.exceptions import NoCredentialsError, BotoCoreError
        except ImportError as e:
            raise RuntimeError(
                "boto3 is required for Bedrock (pip install boto3)."
            ) from e

        session_kwargs: dict[str, Any] = {"region_name": region}
        if profile_name:
            session_kwargs["profile_name"] = profile_name
        elif os.environ.get("AWS_PROFILE"):
            session_kwargs["profile_name"] = os.environ["AWS_PROFILE"]

        try:
            session = boto3.Session(**session_kwargs)
            sts = session.client("sts")
            sts.get_caller_identity()  # fail-fast if creds are missing
        except (NoCredentialsError, BotoCoreError) as e:
            raise RuntimeError(
                f"AWS credentials not usable for profile {profile_name!r}: {e!r}"
            ) from e

        self._client = session.client("bedrock-runtime")
        self.model = model_id
        self._region = region
        self._in_price = input_price_per_mtok
        self._out_price = output_price_per_mtok

    def complete(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
    ) -> LLMResponse:
        body: dict[str, Any] = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
        }
        if tools:
            body["tools"] = tools

        response = self._client.invoke_model(
            modelId=self.model,
            body=json.dumps(body).encode("utf-8"),
            contentType="application/json",
            accept="application/json",
        )
        payload = json.loads(response["body"].read())
        return _normalize(payload, self._in_price, self._out_price)


def _normalize(payload: dict, in_price: float, out_price: float) -> LLMResponse:
    text_parts: list[str] = []
    tool_uses: list[ToolUse] = []
    for block in payload.get("content", []):
        btype = block.get("type")
        if btype == "text":
            text_parts.append(block.get("text", ""))
        elif btype == "tool_use":
            tool_uses.append(
                ToolUse(
                    id=block.get("id", ""),
                    name=block.get("name", ""),
                    arguments=dict(block.get("input") or {}),
                )
            )
    usage = payload.get("usage") or {}
    tokens_in = int(usage.get("input_tokens", 0))
    tokens_out = int(usage.get("output_tokens", 0))
    usd = tokens_in / 1_000_000 * in_price + tokens_out / 1_000_000 * out_price
    return LLMResponse(
        text="\n".join(text_parts),
        tool_uses=tuple(tool_uses),
        stop_reason=str(payload.get("stop_reason", "")),
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        usd_cost=usd,
        raw={"id": payload.get("id")},
    )
