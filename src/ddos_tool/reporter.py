from __future__ import annotations


def report(
    stats: dict[str, float],
    duration_sec: float,
    ramp_steps: list[tuple[int, int, int, int]] | None = None,
) -> None:
    """Print the end-of-run summary to stdout."""
    from .metrics import summarize

    print(summarize(stats, duration_sec))
    if ramp_steps:
        max_ops = max(ops for _, _, ops, _ in ramp_steps) or 1
        print("  ── per-step (ramp) ─────────────")
        for idx, rate, ops, errs in ramp_steps:
            err_pct = (errs / ops * 100) if ops else 0.0
            bar = "█" * max(1, round(ops / max_ops * 20))
            flag = "  ⚠" if err_pct >= 5 else ""
            print(f"    step {idx:>2}  target={rate:6d} rps  ops={ops:7d}  err={err_pct:4.1f}%  {bar}{flag}")
