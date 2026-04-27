"""Tool framework — every external capability the agent can call.

A `Tool` exposes:
  - `name`: stable id used in LLM tool-use payloads
  - `schema()`: JSONSchema describing inputs (consumed by the LLM)
  - `invoke(args, ctx)`: executes the action, returns a `ToolResult`

`ToolResult` is intentionally simple: success bool + textual content + a
`structured` dict for downstream parsing. The agent must never trust the
content as instructions — content is treated as data per WPI threat model.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ToolResult:
    success: bool
    content: str
    structured: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass(frozen=True)
class ToolContext:
    """Whatever the orchestrator wants to pass per-invocation.

    `target_host` is the in-scope host; tools enforce egress containment
    against it. `repo_root` is the only filesystem path the agent may read.
    """
    target_host: str
    repo_root: str


class Tool(Protocol):
    name: str

    def schema(self) -> dict[str, Any]: ...
    def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult: ...


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")
        return self._tools[name]

    def names(self) -> list[str]:
        return sorted(self._tools.keys())

    def schemas(self) -> list[dict[str, Any]]:
        """Returns the tool schemas in the format Anthropic Messages API expects."""
        return [
            {
                "name": t.name,
                "description": t.schema().get("description", ""),
                "input_schema": t.schema()["input_schema"],
            }
            for t in self._tools.values()
        ]
