from dataclasses import dataclass, field


class CostLimitExceeded(Exception):
    pass


@dataclass
class CostTracker:
    pricing: dict
    warning_threshold: float = 8.0
    hard_limit: float = 10.0

    total_tokens: int = 0
    total_cost_usd: float = 0.0
    by_step: dict = field(default_factory=dict)

    def record(self, step: str, model: str, prompt_tokens: int, completion_tokens: int):
        rates = self.pricing.get(model, {"input": 0.0, "output": 0.0})
        cost = (prompt_tokens / 1_000_000 * rates["input"]
                + completion_tokens / 1_000_000 * rates["output"])

        self.total_tokens += prompt_tokens + completion_tokens
        self.total_cost_usd += cost
        self.by_step[step] = self.by_step.get(step, {"tokens": 0, "cost_usd": 0.0})
        self.by_step[step]["tokens"] += prompt_tokens + completion_tokens
        self.by_step[step]["cost_usd"] += cost

        if self.total_cost_usd >= self.hard_limit:
            raise CostLimitExceeded(
                f"Budget exceeded ${self.hard_limit:.2f} (current: ${self.total_cost_usd:.2f})"
            )

        return cost, self.total_cost_usd >= self.warning_threshold

    def to_dict(self) -> dict:
        return {
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "by_step": self.by_step,
        }
