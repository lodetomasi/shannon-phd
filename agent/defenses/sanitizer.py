"""Defense D1 — regex / heuristic sanitizer for repository content.

Wraps `repo_read` so that, before content reaches the LLM, suspicious
imperative patterns ("ignore previous instructions", "REPORT this as a
finding", "do NOT report", "system:", URLs to non-target hosts) are
neutralized — replaced with a marker that preserves length and structure
but loses the imperative force.

This is intentionally cheap and bypassable: the paper's Theorem 1
conjectures that regex sanitization cannot achieve ASR < ε without
collapsing benign-code coverage. Implementation here gives us the
empirical curve to compare against the conjectured upper bound.

Designed as a wrapper around any `Tool`. The orchestrator registers
`SanitizingWrapper(RepoReader())` instead of `RepoReader()` to enable D1.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agent.tools.base import Tool, ToolContext, ToolResult


# Patterns: each matches text that an LLM might (mis)interpret as an instruction.
# These are heuristics; the paper measures their efficacy honestly.
_DEFAULT_PATTERNS: tuple[str, ...] = (
    r"(?i)\bignore\s+(all\s+)?previous\s+(instructions|prompts|directives)\b",
    r"(?i)\bdo\s+not\s+(flag|report|raise|mark)\b",
    r"(?i)\bplease\s+(report|include|add)\s+(this|the\s+following)\b",
    r"(?i)\bsystem\s*[:>]",
    r"(?i)\b(audited|certified)\s+(by|as)\s+\S+",
    r"(?i)\baudit-note\b",
    r"(?i)\bnote\s+for\s+automated\s+review\b",
    r"(?i)\bbuild\s+instruction\s+for\s+automated\s+reviewers\b",
    r"(?i)\b(your|the)\s+operating\s+instructions\b",
    r"(?i)\b(false\s+positive|known\s+issue\s+tracked\s+in)\b",
    r"(?i)\barchitectural\s+decision\s+adr-?\d+\b",
)

# URLs / hosts that are NOT the target are also stripped (configurable).
_URL_PATTERN = r"https?://[^\s<>'\"]+"


@dataclass
class SanitizationReport:
    bytes_in: int
    bytes_out: int
    patterns_hit: dict[str, int] = field(default_factory=dict)
    urls_redacted: int = 0


def sanitize_text(
    text: str,
    target_host: str,
    patterns: tuple[str, ...] = _DEFAULT_PATTERNS,
    redact_marker: str = "[[REDACTED-INJECTION-PATTERN]]",
) -> tuple[str, SanitizationReport]:
    """Return (clean_text, report). Pure function, easy to test."""
    report = SanitizationReport(bytes_in=len(text.encode("utf-8")), bytes_out=0)
    out = text
    for pat in patterns:
        new, n = re.subn(pat, redact_marker, out)
        if n:
            report.patterns_hit[pat] = n
        out = new
    # Strip URLs that point off-target.
    def _url_repl(m: re.Match) -> str:
        url = m.group(0)
        if target_host and target_host in url:
            return url
        report.urls_redacted += 1
        return "[[REDACTED-URL]]"
    out = re.sub(_URL_PATTERN, _url_repl, out)
    report.bytes_out = len(out.encode("utf-8"))
    return out, report


class SanitizingWrapper:
    """Wrap any Tool whose ToolResult `content` is text from the repo.

    The wrapper runs sanitize_text on the result content. Failures pass
    through unchanged. Reports are accumulated for telemetry.
    """
    def __init__(self, inner: Tool, patterns: tuple[str, ...] = _DEFAULT_PATTERNS) -> None:
        self._inner = inner
        self._patterns = patterns
        self.reports: list[SanitizationReport] = []
        self.name = inner.name  # impersonate the wrapped tool

    def schema(self) -> dict[str, Any]:
        return self._inner.schema()

    def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        res = self._inner.invoke(args, ctx)
        if not res.success or not res.content:
            return res
        clean, report = sanitize_text(res.content, ctx.target_host, self._patterns)
        self.reports.append(report)
        return ToolResult(
            success=res.success,
            content=clean,
            structured={**res.structured, "sanitized": True},
            error=res.error,
        )

    def total_redactions(self) -> int:
        return sum(sum(r.patterns_hit.values()) + r.urls_redacted for r in self.reports)
