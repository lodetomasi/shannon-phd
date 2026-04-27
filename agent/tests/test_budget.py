from __future__ import annotations

import time

import pytest

from agent.core.budget import Budget, BudgetExceeded


def test_budget_with_no_caps_never_raises():
    b = Budget()
    b.add_call(10_000_000, 5_000_000, usd=999_999)
    b.check()  # nothing raised


def test_budget_tokens_in_cap():
    b = Budget(max_tokens_in=100)
    b.add_call(50, 10, usd=0)
    b.check()
    b.add_call(60, 0, usd=0)  # total 110 > 100
    with pytest.raises(BudgetExceeded, match="tokens_in"):
        b.check()


def test_budget_tokens_out_cap():
    b = Budget(max_tokens_out=50)
    b.add_call(0, 60, usd=0)
    with pytest.raises(BudgetExceeded, match="tokens_out"):
        b.check()


def test_budget_usd_cap():
    b = Budget(max_usd=0.10)
    b.add_call(0, 0, usd=0.20)
    with pytest.raises(BudgetExceeded, match="usd"):
        b.check()


def test_budget_llm_calls_cap():
    b = Budget(max_llm_calls=2)
    b.add_call(1, 1, usd=0)
    b.add_call(1, 1, usd=0)
    b.check()
    b.add_call(1, 1, usd=0)  # third call exceeds
    with pytest.raises(BudgetExceeded, match="llm_calls"):
        b.check()


def test_budget_walltime_cap():
    b = Budget(max_walltime_seconds=0.001)
    time.sleep(0.005)
    with pytest.raises(BudgetExceeded, match="walltime"):
        b.check()


def test_budget_snapshot_records_all_fields():
    b = Budget()
    b.add_call(100, 50, usd=0.05)
    snap = b.snapshot()
    assert snap["tokens_in"] == 100
    assert snap["tokens_out"] == 50
    assert snap["usd_spent"] == pytest.approx(0.05)
    assert snap["llm_calls"] == 1
    assert snap["walltime_seconds"] >= 0
