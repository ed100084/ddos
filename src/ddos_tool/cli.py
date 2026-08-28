from __future__ import annotations

import asyncio
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


if __name__ == "__main__":
    main()
