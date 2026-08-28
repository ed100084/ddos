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
@click.option("--rps", default=None, type=int, help="Override rate.rps")
@click.option("--quiet", "-q", is_flag=True, help="Suppress live pps output")
def run(config_path: str, duration: float | None, rps: int | None, quiet: bool) -> None:
    """Run a flood against the configured target."""
    data = load_yaml(Path(config_path))
    if duration is not None:
        data["duration_sec"] = duration
    if rps is not None:
        data.setdefault("rate", {})["rps"] = rps
    cfg = Config(**data)

    engine = _build_engine(cfg)
    metrics = Metrics(verbose=not quiet)

    async def go() -> None:
        metrics.begin()

        async def ticker() -> None:
            while True:
                await asyncio.sleep(1.0)
                metrics.tick(engine.stats.get("sent", 0))

        tick_task = asyncio.create_task(ticker())
        try:
            await engine.run()
        finally:
            tick_task.cancel()
            metrics.finish()

    click.echo(f"→ {cfg.attack} flood → {cfg.target} @ {cfg.rate.rps} rps × {cfg.duration_sec}s")
    asyncio.run(go())
    report(engine.stats, cfg.duration_sec)


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
