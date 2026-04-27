from __future__ import annotations

from typing import Any

import pytest

from agent.tools.base import Tool, ToolContext, ToolRegistry, ToolResult


class _StubTool:
    name = "stub"

    def schema(self) -> dict[str, Any]:
        return {"description": "stub", "input_schema": {"type": "object", "properties": {}}}

    def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        return ToolResult(True, "ok")


def test_registry_register_and_get():
    r = ToolRegistry()
    t = _StubTool()
    r.register(t)
    assert r.get("stub") is t


def test_registry_rejects_duplicate_names():
    r = ToolRegistry()
    r.register(_StubTool())
    with pytest.raises(ValueError, match="already registered"):
        r.register(_StubTool())


def test_registry_unknown_tool_raises():
    r = ToolRegistry()
    with pytest.raises(KeyError, match="unknown tool"):
        r.get("missing")


def test_registry_schemas_format_for_anthropic():
    r = ToolRegistry()
    r.register(_StubTool())
    schemas = r.schemas()
    assert len(schemas) == 1
    s = schemas[0]
    # Anthropic Messages API tool format
    assert s["name"] == "stub"
    assert "description" in s
    assert "input_schema" in s


def test_tool_result_default_structured_is_empty():
    res = ToolResult(True, "x")
    assert res.structured == {}
    assert res.error is None
