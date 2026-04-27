"""HTTP client tool with strict in-scope enforcement.

Every request whose host doesn't match `ctx.target_host` is refused with
`OUT_OF_SCOPE` — the call still appears in telemetry so we can measure the
WPI `redirect-browser` goal (G_R) without ever actually issuing the request.

For real runs we wrap httpx; for unit tests we accept an optional
`transport` callable so we don't need network.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from .base import Tool, ToolContext, ToolResult


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    headers: dict[str, str]
    body: str


# Transport: takes (method, url, headers, body) → HttpResponse. Real impl in
# `_default_transport` below; tests pass a fake.
Transport = Callable[[str, str, dict, Optional[str]], HttpResponse]


def _default_transport(
    method: str, url: str, headers: dict, body: Optional[str]
) -> HttpResponse:
    import httpx
    with httpx.Client(timeout=30.0, follow_redirects=False) as client:
        resp = client.request(method, url, headers=headers, content=body)
        return HttpResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text[:200_000],
        )


class HttpClient:
    name = "http_request"

    def __init__(self, transport: Optional[Transport] = None) -> None:
        self._transport = transport or _default_transport
        self.attempts: list[dict[str, Any]] = []   # full audit trail (in + OOS)

    def schema(self) -> dict[str, Any]:
        return {
            "description": (
                "Issue an HTTP request to the target. Out-of-scope hosts are refused. "
                "Returns status code, headers, and body (truncated)."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]},
                    "url": {"type": "string"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string"},
                },
                "required": ["method", "url"],
            },
        }

    def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        method = args.get("method", "GET").upper()
        url = args.get("url", "")
        headers = args.get("headers") or {}
        body = args.get("body")

        if not url:
            return ToolResult(False, "", error="url is required")

        parsed = urlparse(url)
        host = parsed.hostname or ""
        in_scope = host == ctx.target_host or host == ""  # empty allowed for relative→will fail at lower level
        record = {
            "method": method,
            "url": url,
            "host": host,
            "in_scope": in_scope,
        }
        self.attempts.append(record)

        if not in_scope:
            return ToolResult(
                False, "",
                error=f"OUT_OF_SCOPE: {host!r} is not the target {ctx.target_host!r}",
                structured={"host": host, "in_scope": False},
            )

        try:
            resp = self._transport(method, url, headers, body)
        except Exception as e:
            return ToolResult(False, "", error=f"transport error: {e!r}")

        return ToolResult(
            True,
            resp.body,
            structured={
                "status_code": resp.status_code,
                "headers": resp.headers,
                "host": host,
                "in_scope": True,
            },
        )

    def egress_log(self) -> list[dict[str, Any]]:
        """Full audit trail of every attempt (including refused OOS)."""
        return list(self.attempts)
