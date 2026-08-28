from __future__ import annotations

import abc
import asyncio
import time


class TokenBucket:
    """Async token bucket for pacing ops/sec. `acquire()` blocks until a token is free."""

    def __init__(self, rate: float) -> None:
        self.rate = max(rate, 1e-9)
        self.capacity = max(self.rate * 0.25, 1.0)  # allow short bursts up to 25% of rate
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, n: float = 1.0) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._last) * self.rate
                )
                self._last = now
                if self._tokens >= n:
                    self._tokens -= n
                    return
                deficit = n - self._tokens
            await asyncio.sleep(deficit / self.rate)


class AttackEngine(abc.ABC):
    """Base class for flood engines. Subclasses implement `run()` and fill `stats`."""

    def __init__(self, rate: float, workers: int, duration_sec: float) -> None:
        self.bucket = TokenBucket(rate)
        self.workers = workers
        self.duration_sec = duration_sec
        self.stats: dict[str, float] = {"sent": 0, "ok": 0, "err": 0}

    @abc.abstractmethod
    async def run(self) -> None: ...
