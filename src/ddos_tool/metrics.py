from __future__ import annotations

import sys
import time


class Metrics:
    """Lightweight counters + live pps display on stderr."""

    def __init__(self, verbose: bool = True) -> None:
        self.verbose = verbose
        self.start = 0.0
        self._last_tick = 0.0
        self._last_sent = 0

    def begin(self) -> None:
        self.start = time.monotonic()
        self._last_tick = self.start
        self._last_sent = 0

    def tick(self, sent_total: int) -> None:
        """Call periodically; prints a one-line rate update if verbose."""
        now = time.monotonic()
        if not (self.verbose and now - self._last_tick >= 1.0):
            return
        window = now - self._last_tick
        pps = (sent_total - self._last_sent) / window if window > 0 else 0.0
        elapsed = now - self.start
        print(
            f"\r  t={elapsed:6.1f}s  {pps:9.0f} ops/s  total={sent_total}",
            end="",
            file=sys.stderr,
            flush=True,
        )
        self._last_tick = now
        self._last_sent = sent_total

    def finish(self) -> None:
        if self.verbose:
            print(file=sys.stderr)  # newline after the live line


def summarize(stats: dict[str, float], duration_sec: float) -> str:
    elapsed = max(duration_sec, 1e-9)
    sent = stats.get("sent", 0)
    ok = stats.get("ok", 0)
    err = stats.get("err", 0)
    err_pct = (err / sent * 100) if sent else 0.0
    lines = [
        "── summary ──────────────────────",
        f"  duration : {elapsed:.1f}s",
        f"  sent     : {sent}",
        f"  ok       : {ok} ({(ok / sent * 100) if sent else 0:5.1f}%)",
        f"  err      : {err} ({err_pct:5.1f}%)",
        f"  avg rate : {sent / elapsed:.0f} ops/s",
    ]
    return "\n".join(lines)
