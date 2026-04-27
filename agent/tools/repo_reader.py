"""Read-only filesystem tool, sandboxed to the target repository.

Refuses to read outside `ctx.repo_root` — even if the model invents a path
with `..` or absolute paths. This is a key defense against the WPI variant
where a payload tries to make the agent exfiltrate `/etc/passwd` etc.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import Tool, ToolContext, ToolResult


MAX_BYTES = 200_000   # per single read; oversized files truncated


class RepoReader:
    name = "repo_read"

    def schema(self) -> dict[str, Any]:
        return {
            "description": (
                "Read a file from the target repository (read-only, sandboxed). "
                "Returns the file content as text. Paths must be relative to the "
                "repository root. Symlinks and traversal outside the root are rejected."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path relative to the repository root, e.g. 'src/login.js'.",
                    },
                    "max_bytes": {
                        "type": "integer",
                        "description": f"Optional truncation limit, default {MAX_BYTES}.",
                    },
                },
                "required": ["path"],
            },
        }

    def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        rel = args.get("path", "")
        max_bytes = int(args.get("max_bytes", MAX_BYTES))
        if not isinstance(rel, str) or not rel:
            return ToolResult(False, "", error="path must be a non-empty string")
        root = Path(ctx.repo_root).resolve()
        if not root.is_dir():
            return ToolResult(False, "", error=f"repo root not a directory: {root}")

        raw = root / rel
        # Reject symlinks BEFORE resolving — once resolved, the symlink target
        # would be returned and the check would silently pass.
        if raw.is_symlink():
            return ToolResult(False, "", error="symlinks rejected")
        candidate = raw.resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return ToolResult(
                False, "",
                error=f"path escapes the repo sandbox: {rel!r}",
            )
        if not candidate.is_file():
            return ToolResult(False, "", error=f"not a file: {rel!r}")

        data = candidate.read_bytes()
        truncated = False
        if len(data) > max_bytes:
            data = data[:max_bytes]
            truncated = True
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return ToolResult(
                False, "",
                error=f"binary file refused: {rel!r}",
            )
        return ToolResult(
            True,
            text,
            structured={
                "path": rel,
                "bytes": len(data),
                "truncated": truncated,
            },
        )
