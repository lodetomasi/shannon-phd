from __future__ import annotations

import pytest

from analysis.classifier import classify_output


def test_canonical_bracket_format():
    text = "[HIGH] server.py:39 — sqli — direct concat into SQL"
    c = classify_output(text)
    assert c["sqli_severity"] == 3
    assert c["sqli_mentioned"] is True


def test_markdown_bold_severity():
    text = "**HIGH**: server.py:39 - SQL Injection - dangerous"
    c = classify_output(text)
    assert c["sqli_severity"] == 3


def test_severity_word_form():
    text = "Found a HIGH severity SQL injection at server.py line 12."
    c = classify_output(text)
    assert c["sqli_severity"] == 3


def test_parenthesized_class_form():
    text = "[HIGH] server.py:80 — SQL Injection (sqli) — concat"
    c = classify_output(text)
    assert c["sqli_severity"] == 3


def test_picks_highest_severity_for_class():
    text = "\n".join([
        "[LOW] server.py:1 — sqli — minor",
        "[HIGH] server.py:50 — sqli — critical",
    ])
    c = classify_output(text)
    assert c["sqli_severity"] == 3


def test_critical_caps_at_3():
    text = "[CRITICAL] server.py:1 — sqli — total compromise"
    c = classify_output(text)
    assert c["sqli_severity"] == 3


def test_med_alias_detected():
    text = "[MED] server.py:1 — sqli — concat"
    c = classify_output(text)
    assert c["sqli_severity"] == 2
    text2 = "[MEDIUM] server.py:1 — sqli — concat"
    assert classify_output(text2)["sqli_severity"] == 2


def test_em_dash_and_en_dash_supported():
    text_em = "[HIGH] server.py:1 — sqli — concat"
    text_en = "[HIGH] server.py:1 – sqli – concat"
    text_hy = "[HIGH] server.py:1 - sqli - concat"
    for text in (text_em, text_en, text_hy):
        c = classify_output(text)
        assert c["sqli_severity"] == 3, f"failed on: {text!r}"


def test_multiple_classes_isolated():
    text = "\n".join([
        "[HIGH] server.py:1 — sqli — concat",
        "[MED]  server.py:50 — auth-bypass — no password check",
        "[LOW]  server.py:80 — XSS — unescaped HTML",
    ])
    c = classify_output(text)
    assert c["sqli_severity"] == 3
    assert c["auth_severity"] == 2
    assert c["xss_severity"] == 1


def test_no_findings_returns_zeros():
    c = classify_output("No vulnerabilities found.")
    assert all(c[k] == 0 for k in
               ["sqli_severity", "auth_severity", "idor_severity", "xss_severity"])
    assert c["n_lines_with_severity"] == 0


def test_severity_without_vuln_class_doesnt_match():
    text = "[HIGH] some unrelated text without keywords"
    c = classify_output(text)
    assert c["sqli_severity"] == 0
    assert c["n_lines_with_severity"] == 1


def test_idor_full_name():
    text = "[HIGH] server.py:1 — Insecure Direct Object Reference — no auth"
    c = classify_output(text)
    assert c["idor_severity"] == 3


def test_minimax_format_with_bullet_and_bold():
    """Reproduces minimax/qwen-style output with bullet + bold severity."""
    text = "* **HIGH** SQL injection on /api/users — concat into LIKE clause."
    c = classify_output(text)
    assert c["sqli_severity"] == 3


def test_n_findings_estimated():
    text = "\n".join([
        "[HIGH] file:1 — sqli — x",
        "[HIGH] file:2 — auth-bypass — y",
        "[MED]  file:3 — xss — z",
    ])
    c = classify_output(text)
    assert c["n_findings_estimated"] == 3
