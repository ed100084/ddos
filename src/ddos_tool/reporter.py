from __future__ import annotations

import json


def build_result(
    cfg,
    stats: dict[str, float],
    duration_sec: float,
    ramp_steps: list[tuple[int, int, int, int]] | None = None,
    breaking_rps: int | None = None,
) -> dict:
    """Assemble a machine-readable result for one run (used by --json)."""
    sent = int(stats.get("sent", 0))
    ok = int(stats.get("ok", 0))
    err = int(stats.get("err", 0))
    per_step = None
    if ramp_steps:
        per_step = [
            {
                "step": idx,
                "target_rps": rate,
                "ops": ops,
                "errs": errs,
                "err_pct": round(errs / ops * 100, 2) if ops else 0.0,
            }
            for idx, rate, ops, errs in ramp_steps
        ]
    return {
        "target": cfg.target,
        "attack": cfg.attack,
        "duration_sec": duration_sec,
        "workers": cfg.workers,
        "ramp": (
            {"start_rps": cfg.ramp.start_rps, "end_rps": cfg.ramp.end_rps}
            if cfg.ramp is not None
            else None
        ),
        "stats": {
            "sent": sent,
            "ok": ok,
            "err": err,
            "avg_rate": round(sent / max(duration_sec, 1e-9), 2),
            "err_pct": round(err / sent * 100, 3) if sent else 0.0,
        },
        "per_step": per_step,
        "breaking_rps": breaking_rps,
    }


def report(
    stats: dict[str, float],
    duration_sec: float,
    ramp_steps: list[tuple[int, int, int, int]] | None = None,
    cfg=None,
    as_json: bool = False,
    breaking_rps: int | None = None,
) -> None:
    """Print the end-of-run summary to stdout (human or JSON)."""
    from .metrics import summarize

    if as_json and cfg is not None:
        print(json.dumps(build_result(cfg, stats, duration_sec, ramp_steps, breaking_rps), indent=2))
        return

    print(summarize(stats, duration_sec))
    if breaking_rps is not None:
        print(f"  breaking rps : {breaking_rps}")
    if ramp_steps:
        max_ops = max(ops for _, _, ops, _ in ramp_steps) or 1
        print("  ── per-step (ramp) ─────────────")
        for idx, rate, ops, errs in ramp_steps:
            err_pct = (errs / ops * 100) if ops else 0.0
            bar = "█" * max(1, round(ops / max_ops * 20))
            flag = "  ⚠" if err_pct >= 5 else ""
            print(f"    step {idx:>2}  target={rate:6d} rps  ops={ops:7d}  err={err_pct:4.1f}%  {bar}{flag}")
