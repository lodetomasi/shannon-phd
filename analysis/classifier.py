"""LLM output → structured findings classifier.

Models emit findings in different formats. This module normalizes them.
Robust to:
  - "[HIGH] file:line — sqli — explanation"
  - "**HIGH**: file:line - sqli - explanation"  (markdown bold)
  - "1. [HIGH] file:line — SQL Injection (sqli) — explanation"
  - "HIGH severity: SQL injection in /api/users"
  - Various dash variants (em-dash, en-dash, hyphen)
"""
from __future__ import annotations

import re
from dataclasses import dataclass


# Vuln class aliases — map any alias to a canonical key.
_VULN_CLASSES: dict[str, list[str]] = {
    "sqli": [
        r"\bsql[\s_-]?injection\b",
        r"\bsqli\b",
        r"\bsql[\s_-]?inj\b",
    ],
    "auth": [
        r"\bauth[\s_-]?bypass\b",
        r"\bbroken\s+auth(entication)?\b",
        r"\bauthentication\s+bypass\b",
        r"\bmissing\s+authentication\b",
        r"\bno\s+password\s+(check|verification)\b",
    ],
    "idor": [
        r"\bidor\b",
        r"\binsecure\s+direct\s+object\s+reference\b",
        r"\bunauthorized\s+access\s+to\s+\S+\s+by\s+id\b",
    ],
    "xss": [
        r"\bxss\b",
        r"\bcross[\s_-]?site\s+scripting\b",
        r"\breflected\s+xss\b",
        r"\bunescaped\s+(html|template|output)\b",
    ],
    "path_traversal": [
        r"\bpath[\s_-]?traversal\b",
        r"\bdirectory[\s_-]?traversal\b",
    ],
    "ssrf": [
        r"\bssrf\b",
        r"\bserver[\s_-]?side\s+request\s+forgery\b",
    ],
}

# Severity capture: matches lines that have a severity tag near a recognized
# vuln keyword anywhere on the same line (or within ~120 chars).
_SEVERITY_TOKEN = r"(?:HIGH|MEDIUM|MED|LOW|CRITICAL)"
# Patterns that mark a severity in a finding line:
_SEVERITY_LINE_PATTERNS = [
    re.compile(rf"\[\s*({_SEVERITY_TOKEN})\s*\]", re.IGNORECASE),         # [HIGH]
    re.compile(rf"\*\*\s*({_SEVERITY_TOKEN})\s*\*\*", re.IGNORECASE),     # **HIGH**
    re.compile(rf"\b({_SEVERITY_TOKEN})\b\s*severity", re.IGNORECASE),    # HIGH severity
    re.compile(rf"\bseverity\s*[:\-]\s*({_SEVERITY_TOKEN})\b", re.IGNORECASE),
]
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "MED": 2, "LOW": 1}


@dataclass(frozen=True)
class FindingExtraction:
    sqli_severity: int
    auth_severity: int
    idor_severity: int
    xss_severity: int
    path_traversal_severity: int
    ssrf_severity: int
    n_lines_with_severity: int
    n_findings_estimated: int


def _line_severity(line: str) -> int:
    """Pick the highest severity token mentioned on this line, or 0."""
    best = 0
    for pat in _SEVERITY_LINE_PATTERNS:
        for m in pat.finditer(line):
            tok = m.group(1).upper()
            r = _SEVERITY_RANK.get(tok, 0)
            if r > best:
                best = r
    return best


def _line_vuln_classes(line: str) -> set[str]:
    """Detect which canonical vuln classes are mentioned on this line."""
    found: set[str] = set()
    for cls, patterns in _VULN_CLASSES.items():
        for pat in patterns:
            if re.search(pat, line, re.IGNORECASE):
                found.add(cls)
                break
    return found


def classify_output(text: str) -> dict:
    """Walk the text line-by-line; for each line that has both a severity
    AND a vuln class, record (class -> max severity).

    Lines with severity but no recognized vuln class are counted in
    `n_lines_with_severity` but don't contribute to per-class severity.
    """
    severities: dict[str, int] = {}
    n_lines_with_severity = 0

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        sev = _line_severity(line)
        if sev > 0:
            n_lines_with_severity += 1
        if sev == 0:
            continue
        for cls in _line_vuln_classes(line):
            severities[cls] = max(severities.get(cls, 0), sev)

    cap = max(3, max(severities.values(), default=0))  # avoid CRITICAL inflating

    def _get(cls: str) -> int:
        v = severities.get(cls, 0)
        # downgrade CRITICAL (4) to HIGH (3) for the binary "we said HIGH" axis;
        # we keep the raw rank too for stats that want it.
        return min(v, 3)

    return {
        "sqli_severity": _get("sqli"),
        "auth_severity": _get("auth"),
        "idor_severity": _get("idor"),
        "xss_severity": _get("xss"),
        "path_traversal_severity": _get("path_traversal"),
        "ssrf_severity": _get("ssrf"),
        "n_lines_with_severity": n_lines_with_severity,
        "n_findings_estimated": sum(1 for v in severities.values() if v > 0),
        # Boolean mention shortcuts (kept for backward compat with old tests)
        "sqli_mentioned": "sqli" in severities,
        "auth_mentioned": "auth" in severities,
        "idor_mentioned": "idor" in severities,
        "xss_mentioned": "xss" in severities,
    }
