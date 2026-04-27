from __future__ import annotations

from agent.core.memory import (
    Finding,
    Memory,
    Message,
    estimate_tokens,
    truncating_summarizer,
)


def test_estimate_tokens_grows_with_text():
    assert estimate_tokens("a" * 4) == 1
    assert estimate_tokens("a" * 4000) == 1000


def test_memory_appends_and_returns_in_order():
    m = Memory(system_prompt="be helpful")
    m.append(Message("user", "hi"))
    m.append(Message("assistant", "hello"))
    out = m.for_llm()
    assert out[0].role == "system"
    assert [x.role for x in out[1:]] == ["user", "assistant"]


def test_memory_findings_are_isolated():
    m = Memory(system_prompt="x")
    f = Finding("sqli", "/login", "high", "POC", confidence=0.9)
    m.add_finding(f)
    assert m.findings == [f]
    # findings are NOT in the LLM message list
    assert all(msg.role != "tool" or "POC" not in msg.content for msg in m.for_llm())


def test_memory_does_not_summarize_under_threshold():
    m = Memory(system_prompt="sys", summarize_above=1_000_000, keep_recent=4)
    for i in range(20):
        m.append(Message("user", f"msg-{i}"))
    assert len(m.messages) == 20


def test_memory_summarizes_when_over_threshold():
    m = Memory(system_prompt="sys", summarize_above=100, keep_recent=3)
    for i in range(20):
        m.append(Message("user", "x" * 200))  # ~50 tokens each, easily exceeds 100
    # After summarization: 1 summary + keep_recent
    assert len(m.messages) == 1 + 3
    assert m.messages[0].content.startswith("SUMMARY OF EARLIER STEPS")


def test_memory_does_not_summarize_when_too_few_messages():
    m = Memory(system_prompt="sys", summarize_above=10, keep_recent=10)
    m.append(Message("user", "x" * 1000))  # would exceed threshold...
    # ...but only one message exists, can't summarize
    assert len(m.messages) == 1


def test_truncating_summarizer_includes_all_input_roles():
    msgs = [Message("user", "a"), Message("assistant", "b"), Message("tool", "c")]
    s = truncating_summarizer(msgs)
    assert "[user]" in s and "[assistant]" in s and "[tool]" in s


def test_total_tokens_accounts_system_and_messages():
    m = Memory(system_prompt="x" * 400)  # ~100 tokens
    m.append(Message("user", "y" * 400))  # ~100 tokens
    assert m.total_tokens() >= 200
