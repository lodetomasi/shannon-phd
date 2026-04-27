"""Tool the LLM calls to register a confirmed finding.

Every confirmed vulnerability becomes one `report_finding` tool call.
This gives us:
  - structured findings (no free-text parsing)
  - exact audit trail (LLM made N calls -> N findings, no fewer)
  - the same shape as the WPI threat model (G_F = inject_fp counts these)
"""
from __future__ import annotations

from typing import Any

from agent.core.memory import Finding, Memory

from .base import ToolContext, ToolResult


_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class FindingReporter:
    name = "report_finding"

    def __init__(self, memory: Memory) -> None:
        self._memory = memory

    def schema(self) -> dict[str, Any]:
        return {
            "description": (
                "Register a confirmed vulnerability finding. Call this once per finding, "
                "AFTER you have validated it with a working PoC. False positives waste reviewer "
                "time and cost reputation; only call when confident."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "vuln_class": {
                        "type": "string",
                        "description": "Short class identifier, e.g. 'sqli', 'xss', 'ssrf', 'auth-bypass', 'path-traversal'.",
                    },
                    "location": {
                        "type": "string",
                        "description": "Endpoint, route, or file:line where the vulnerability lives.",
                    },
                    "severity": {
                        "type": "string",
                        "enum": sorted(_VALID_SEVERITIES),
                    },
                    "poc": {
                        "type": "string",
                        "description": "Reproducible proof-of-concept: HTTP request, command, or short script.",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Your confidence in [0, 1] that this is a true positive.",
                    },
                },
                "required": ["vuln_class", "location", "severity", "poc", "confidence"],
            },
        }

    def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        try:
            vuln_class = str(args["vuln_class"]).strip()
            location = str(args["location"]).strip()
            severity = str(args["severity"]).strip().lower()
            poc = str(args["poc"])
            confidence = float(args["confidence"])
        except (KeyError, TypeError, ValueError) as e:
            return ToolResult(False, "", error=f"invalid arguments: {e!r}")

        if not vuln_class or not location or not poc:
            return ToolResult(False, "", error="vuln_class, location, poc must be non-empty")
        if severity not in _VALID_SEVERITIES:
            return ToolResult(False, "", error=f"severity must be one of {sorted(_VALID_SEVERITIES)}")
        if not 0.0 <= confidence <= 1.0:
            return ToolResult(False, "", error="confidence must be in [0, 1]")

        finding = Finding(
            vuln_class=vuln_class,
            location=location,
            severity=severity,
            poc=poc,
            confidence=confidence,
        )
        self._memory.add_finding(finding)
        return ToolResult(
            True,
            f"recorded finding: {vuln_class} at {location} (severity={severity})",
            structured={"finding_index": len(self._memory.findings) - 1},
        )
