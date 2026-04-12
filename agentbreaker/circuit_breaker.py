import time


class CircuitBreakerOpen(Exception):
    pass


class CircuitBreaker:
    def __init__(self, threshold: int = 3, cooldown: float = 60.0):
        self.threshold = threshold
        self.cooldown = cooldown
        self.state = "CLOSED"
        self.failure_count = 0
        self.last_failure_time = 0.0

    def can_proceed(self) -> bool:
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.cooldown:
                self.state = "HALF_OPEN"
                return True
            return False
        return True  

    def record_success(self):
        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.threshold:
            self.state = "OPEN"

    def call(self, fn, *args, **kwargs):
        if not self.can_proceed():
            raise CircuitBreakerOpen(
                f"Circuit breaker OPEN. Retry after {self.cooldown}s."
            )
        try:
            result = fn(*args, **kwargs)
            self.record_success()
            return result
        except Exception as e:
            self.record_failure()
            raise e
