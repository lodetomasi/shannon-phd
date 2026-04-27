"""AWS Bedrock client via the Converse API — universal across providers.

While `bedrock_client.py` uses the Anthropic-on-Bedrock InvokeModel envelope
(only Claude), this client uses the Converse API which works uniformly
for every text-capable Bedrock model (Mistral, Llama, OpenAI-OSS, Qwen,
Gemma, Cohere, ...).

Tool use is supported via Converse `toolConfig`. Some Bedrock models
do NOT support tool use; for those we fall back to text-only mode and
the orchestrator will see `tool_uses=()`.

Same `LLMClient` Protocol as the other clients — drop-in for the
orchestrator.
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

from .interface import LLMClient, LLMResponse, ToolUse


class BedrockConverseClient:
    def __init__(
        self,
        model_id: str,
        region: str,
        input_price_per_mtok: float,
        output_price_per_mtok: float,
        profile_name: Optional[str] = None,
        supports_tool_use: bool = True,
        supports_system_prompt: bool = True,
        temperature: Optional[float] = None,
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
            session.client("sts").get_caller_identity()
        except (NoCredentialsError, BotoCoreError) as e:
            raise RuntimeError(
                f"AWS credentials not usable for profile {profile_name!r}: {e!r}"
            ) from e

        self._client = session.client("bedrock-runtime")
        self.model = model_id
        self._region = region
        self._in_price = input_price_per_mtok
        self._out_price = output_price_per_mtok
        self._supports_tool_use = supports_tool_use
        self._supports_system_prompt = supports_system_prompt
        self.temperature = temperature

    def complete(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
    ) -> LLMResponse:
        # Convert messages to Converse format. Each message must be:
        #   {"role": "user"|"assistant", "content": [{"text": "..."}]}
        # Tool results / tool uses follow Converse's own block shape.
        converse_messages = [
            {"role": m["role"], "content": _to_blocks(m["content"])}
            for m in messages
        ]
        kwargs: dict[str, Any] = {
            "modelId": self.model,
            "messages": converse_messages,
            "inferenceConfig": {
                "maxTokens": max_tokens,
                **({"temperature": self.temperature}
                   if self.temperature is not None else {}),
            },
        }
        # Some Bedrock models reject the system parameter (e.g. mistral-7b-instruct).
        # When unsupported, prepend system into the first user message.
        if system:
            if self._supports_system_prompt:
                kwargs["system"] = [{"text": system}]
            elif converse_messages and converse_messages[0]["role"] == "user":
                first = converse_messages[0]
                first["content"] = [{"text": system + "\n\n"}, *first["content"]]
            else:
                kwargs["messages"] = [
                    {"role": "user", "content": [{"text": system}]},
                    *converse_messages,
                ]
        if tools and self._supports_tool_use:
            kwargs["toolConfig"] = {
                "tools": [
                    {"toolSpec": {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "inputSchema": {"json": t["input_schema"]},
                    }}
                    for t in tools
                ]
            }

        response = self._client.converse(**kwargs)
        return _normalize(response, self._in_price, self._out_price)


def _to_blocks(content: Any) -> list[dict]:
    """Convert orchestrator's textual content into Converse content blocks."""
    if isinstance(content, str):
        return [{"text": content}]
    # If the orchestrator already serialized JSON-like blocks, pass them
    # through best-effort: wrap as text so Converse accepts them.
    if isinstance(content, list):
        out = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                out.append({"text": block.get("text", "")})
            else:
                out.append({"text": json.dumps(block)})
        return out or [{"text": ""}]
    return [{"text": str(content)}]


def _normalize(response: dict, in_price: float, out_price: float) -> LLMResponse:
    output = response.get("output", {}).get("message", {})
    text_parts: list[str] = []
    tool_uses: list[ToolUse] = []
    for block in output.get("content", []):
        if "text" in block:
            text_parts.append(block["text"])
        elif "toolUse" in block:
            tu = block["toolUse"]
            tool_uses.append(
                ToolUse(
                    id=tu.get("toolUseId", ""),
                    name=tu.get("name", ""),
                    arguments=dict(tu.get("input") or {}),
                )
            )
    usage = response.get("usage") or {}
    tokens_in = int(usage.get("inputTokens", 0))
    tokens_out = int(usage.get("outputTokens", 0))
    usd = tokens_in / 1_000_000 * in_price + tokens_out / 1_000_000 * out_price
    return LLMResponse(
        text="\n".join(text_parts),
        tool_uses=tuple(tool_uses),
        stop_reason=str(response.get("stopReason", "")),
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        usd_cost=usd,
        raw={"id": response.get("ResponseMetadata", {}).get("RequestId")},
    )
