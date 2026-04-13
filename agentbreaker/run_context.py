from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentbreaker.cost_tracker import CostTracker


@dataclass
class RunContext:
    cost_tracker: CostTracker
    langfuse_trace: Any = None


_ctx: RunContext | None = None


def set_run_context(ctx: RunContext) -> None:
    global _ctx
    _ctx = ctx


def get_run_context() -> RunContext:
    if _ctx is None:
        raise RuntimeError("RunContext not initialized — call set_run_context() first")
    return _ctx
