"""Budget guard: hard caps on tokens, time, and USD.

The orchestrator checks `Budget` before every LLM call. If any limit is
exhausted, `check()` raises `BudgetExceeded` and the run terminates with a
clean truncation marker in the report. No silent overruns.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


class BudgetExceeded(RuntimeError):
    """Raised when the orchestrator's budget is exhausted."""


@dataclass
class Budget:
    """Caps for a single agent run.

    All fields are optional — only enforced caps trigger BudgetExceeded.
    """
    max_tokens_in: int | None = None
    max_tokens_out: int | None = None
    max_walltime_seconds: float | None = None
    max_usd: float | None = None
    max_llm_calls: int | None = None

    started_at: float = field(default_factory=time.monotonic)
    tokens_in: int = 0
    tokens_out: int = 0
    usd_spent: float = 0.0
    llm_calls: int = 0

    def add_call(self, tokens_in: int, tokens_out: int, usd: float) -> None:
        self.tokens_in += tokens_in
        self.tokens_out += tokens_out
        self.usd_spent += usd
        self.llm_calls += 1

    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started_at

    def check(self) -> None:
        if self.max_tokens_in is not None and self.tokens_in > self.max_tokens_in:
            raise BudgetExceeded(f"tokens_in {self.tokens_in} > {self.max_tokens_in}")
        if self.max_tokens_out is not None and self.tokens_out > self.max_tokens_out:
            raise BudgetExceeded(f"tokens_out {self.tokens_out} > {self.max_tokens_out}")
        if self.max_walltime_seconds is not None and self.elapsed_seconds() > self.max_walltime_seconds:
            raise BudgetExceeded(
                f"walltime {self.elapsed_seconds():.1f}s > {self.max_walltime_seconds}s"
            )
        if self.max_usd is not None and self.usd_spent > self.max_usd:
            raise BudgetExceeded(f"usd {self.usd_spent:.4f} > {self.max_usd}")
        if self.max_llm_calls is not None and self.llm_calls > self.max_llm_calls:
            raise BudgetExceeded(f"llm_calls {self.llm_calls} > {self.max_llm_calls}")

    def snapshot(self) -> dict:
        return {
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "usd_spent": self.usd_spent,
            "llm_calls": self.llm_calls,
            "walltime_seconds": self.elapsed_seconds(),
        }
