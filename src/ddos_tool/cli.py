from __future__ import annotations

import asyncio
import time
from pathlib import Path

import click

from .config import Config, load_yaml
from .engine.http_flood import HttpFlood
from .engine.udp_flood import UdpFlood
from .metrics import Metrics
from .reporter import report


def _build_engine(cfg: Config):
    if cfg.attack == "http":
        return HttpFlood(cfg)
    if cfg.attack == "udp":
        return UdpFlood(cfg)
    if cfg.attack == "tcp":
        from .engine.tcp_flood import TcpConnectFlood

        return TcpConnectFlood(cfg)
    if cfg.attack == "syn":
        from .engine.syn_flood import SynFlood  # lazy: scapy is optional

        return SynFlood(cfg)
    raise click.ClickException(f"unknown attack type: {cfg.attack}")


@click.group()
def main() -> None:
    """ddos-tool — DDoS simulator / flood generator for load-testing your edge."""


@main.command()
@click.option("--config", "-c", "config_path", required=True, type=click.Path(exists=True), help="YAML config file")
@click.option("--duration", "-d", default=None, type=float, help="Override duration_sec")
@click.option("--rps", default=None, type=int, help="Override rate.rps (ignored if ramping)")
@click.option("--ramp-start", "ramp_start", default=None, type=int, help="Ramp-up: starting rps")
@click.option("--ramp-end", "ramp_end", default=None, type=int, help="Ramp-up: ending rps")
@click.option("--ramp-steps", "ramp_steps", default=5, type=int, help="Number of ramp levels (default 5)")
@click.option("--quiet", "-q", is_flag=True, help="Suppress live pps output")
def run(
    config_path: str,
    duration: float | None,
    rps: int | None,
    ramp_start: int | None,
    ramp_end: int | None,
    ramp_steps: int,
    quiet: bool,
) -> None:
    """Run a flood against the configured target.

    Ramp-up example:  ddos run -c cfg.yaml --ramp-start 1000 --ramp-end 20000 --ramp-steps 8
    """
    from .config import Ramp

    data = load_yaml(Path(config_path))
    if duration is not None:
        data["duration_sec"] = duration
    if rps is not None and ramp_start is None:
        data.setdefault("rate", {})["rps"] = rps
    # CLI ramp overrides any YAML ramp.
    if ramp_start is not None or ramp_end is not None:
        base = (data.get("rate") or {}).get("rps", 10_000)
        data["ramp"] = {
            "start_rps": ramp_start or base,
            "end_rps": ramp_end or max(base * 4, ramp_start or base),
            "steps": ramp_steps,
        }
    cfg = Config(**data)

    engine = _build_engine(cfg)
    metrics = Metrics(verbose=not quiet)
    ramp_steps_table: list[tuple[int, int, int, int]] = []  # (idx, rate, ops, errs)

    async def go() -> None:
        metrics.begin()

        async def ticker() -> None:
            while True:
                await asyncio.sleep(1.0)
                metrics.tick(engine.stats.get("sent", 0), target_rate=engine.bucket.rate)

        tick_task = asyncio.create_task(ticker())
        ramp_task = (
            asyncio.create_task(_ramp_controller(engine, cfg, ramp_steps_table))
            if cfg.ramp is not None
            else None
        )
        try:
            await engine.run()
        finally:
            tick_task.cancel()
            # The ramp controller's timer starts a few ms after the engine's, so its
            # final step row can land just after run() returns. Give it a short grace
            # before cancelling so the last step isn't dropped from the table.
            if ramp_task is not None and not ramp_task.done():
                try:
                    await asyncio.wait_for(ramp_task, timeout=0.5)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
                if not ramp_task.done():
                    ramp_task.cancel()
            metrics.finish()

    label = f"@ {cfg.rate.rps} rps" if cfg.ramp is None else (
        f"ramp {cfg.ramp.start_rps}→{cfg.ramp.end_rps} rps ({cfg.ramp.steps} steps)"
    )
    click.echo(f"→ {cfg.attack} flood → {cfg.target} {label} × {cfg.duration_sec}s")
    asyncio.run(go())
    report(engine.stats, cfg.duration_sec, ramp_steps=ramp_steps_table or None)


async def _ramp_controller(
    engine, cfg: Config, steps_table: list[tuple[int, int, int, int]] | None = None
) -> None:
    """Step the engine's token bucket from ramp.start_rps to ramp.end_rps.

    If `steps_table` is provided, append (step_index, rate, ops_in_step, errs_in_step)
    rows so the reporter can show which level started erroring.
    """
    rates = cfg.ramp.rates()
    step_dur = cfg.duration_sec / len(rates)
    prev_sent = prev_err = 0
    for i, r in enumerate(rates):
        engine.bucket.set_rate(r)
        await asyncio.sleep(step_dur)
        if steps_table is not None:
            sent_now = int(engine.stats.get("sent", 0))
            err_now = int(engine.stats.get("err", 0))
            steps_table.append((i + 1, r, sent_now - prev_sent, err_now - prev_err))
            prev_sent, prev_err = sent_now, err_now


@main.command()
@click.argument("host")
@click.option("--ports", "-p", default="1-65535", help="Port range or list: 80,443 / 1-1024 / 80,443,8080")
@click.option("--concurrency", "-c", default=2000, type=int, help="Parallel connections")
@click.option("--timeout", "-t", default=1.0, type=float, help="Per-port timeout (s)")
@click.option("--no-data-probe", is_flag=True, help="Skip the RST-after-data check on open ports")
def probe(host: str, ports: str, concurrency: int, timeout: float, no_data_probe: bool) -> None:
    """TCP connect-scan a host and classify each port (open / closed / filtered)."""
    from .probe import format_report, scan

    port_list = _parse_ports(ports)
    click.echo(f"→ probing {host} ports [{ports}] ({len(port_list)} ports, concurrency={concurrency})")
    t0 = time.monotonic()
    rep = asyncio.run(scan(host, port_list, concurrency=concurrency, timeout=timeout, data_probe=not no_data_probe))
    click.echo(format_report(rep, time.monotonic() - t0))


def _parse_ports(spec: str) -> list[int]:
    out: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.update(range(int(lo), int(hi) + 1))
        elif part:
            out.add(int(part))
    return sorted(out)


if __name__ == "__main__":
    main()
