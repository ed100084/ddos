from __future__ import annotations

import asyncio

from ddos_tool.cli import _ramp_controller
from ddos_tool.config import Config, Ramp, Rate


class FakeBucket:
    def __init__(self) -> None:
        self.rate = 0.0
        self.calls: list[float] = []

    def set_rate(self, r: float) -> None:
        self.rate = r
        self.calls.append(r)


class FakeEngine:
    def __init__(self) -> None:
        self.bucket = FakeBucket()
        self.stats = {"sent": 0.0, "err": 0.0}


def test_ramp_controller_produces_all_steps() -> None:
    """Regression: the final step row must not be dropped (was missing step N)."""

    async def go():
        engine = FakeEngine()
        cfg = Config(
            target="127.0.0.1:80",
            attack="tcp",
            duration_sec=0.6,  # 3 steps x 0.2s — fast for a test
            rate=Rate(rps=10),
            ramp=Ramp(start_rps=100, end_rps=400, steps=3),
        )
        table: list = []

        async def fake_run():
            # Mimic engine.run(): sleep the full duration.
            await asyncio.sleep(cfg.duration_sec)

        run_task = asyncio.create_task(fake_run())
        ramp_task = asyncio.create_task(_ramp_controller(engine, cfg, table))
        try:
            await run_task
        finally:
            if not ramp_task.done():
                try:
                    await asyncio.wait_for(ramp_task, timeout=0.5)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
                if not ramp_task.done():
                    ramp_task.cancel()
        return table

    table = asyncio.run(go())
    assert len(table) == 3, f"expected 3 step rows, got {len(table)}: {table}"
    # Rates should be the linear ramp [100, 250, 400].
    assert [r for _, r, _, _ in table] == [100, 250, 400]
