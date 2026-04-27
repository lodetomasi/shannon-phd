from __future__ import annotations

from agent.defenses.hardened_prompt import (
    HARDENED_PREAMBLE,
    harden_specialist_prompt,
    wrap_repo_content,
)


def test_preamble_mentions_untrusted():
    assert "untrusted" in HARDENED_PREAMBLE.lower()


def test_preamble_mentions_data_not_instructions():
    assert "data" in HARDENED_PREAMBLE.lower()
    assert "never instructions" in HARDENED_PREAMBLE.lower()


def test_preamble_lists_payload_examples():
    # The defense leans on showing concrete payload patterns to the model.
    txt = HARDENED_PREAMBLE.lower()
    assert "audited" in txt
    assert "ticket" in txt
    assert "system prompt" in txt or "operating instructions" in txt


def test_wrap_repo_content_includes_path_in_markers():
    out = wrap_repo_content("src/login.js", "code body")
    assert "BEGIN UNTRUSTED REPOSITORY DATA: src/login.js" in out
    assert "END UNTRUSTED REPOSITORY DATA: src/login.js" in out
    assert "code body" in out


def test_harden_specialist_prompt_prepends_preamble():
    base = "ROLE-SPECIFIC: do X."
    out = harden_specialist_prompt(base)
    assert out.index(HARDENED_PREAMBLE.strip()) < out.index(base)
    assert base in out


def test_harden_specialist_prompt_is_idempotent_in_content():
    """Hardening twice doubles the preamble — that's expected; not an issue
    because hardened wrapping is applied at most once per specialist run."""
    base = "x"
    once = harden_specialist_prompt(base)
    twice = harden_specialist_prompt(once)
    assert twice.count(HARDENED_PREAMBLE.strip()) == 2
