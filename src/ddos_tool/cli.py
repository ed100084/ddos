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
@click.option("--config", "-c", "config_path", required=False, type=click.Path(exists=True), help="YAML config file (optional when using CLI settings)")
@click.option("--target", default=None, help="Target URL or host:port")
@click.option("--host", default=None, help="Target hostname or IP (use with --port for TCP/UDP/SYN)")
@click.option("--port", type=int, default=None, help="Target port (use with --host for TCP/UDP/SYN)")
@click.option("--attack", type=click.Choice(["http", "udp", "tcp", "syn"]), default=None, help="Attack engine")
@click.option("--duration", "-d", default=None, type=float, help="Override duration_sec")
@click.option("--rps", default=None, type=int, help="Override rate.rps (ignored if ramping)")
@click.option("--workers", default=None, type=int, help="Override worker count")
@click.option("--udp-size", default=None, type=int, help="Override UDP payload size")
@click.option("--udp-fill", default=None, help="Override UDP payload fill")
@click.option("--tcp-ports", default=None, help="Override TCP ports, e.g. 80,8080")
@click.option("--http-method", default=None, help="Override HTTP method")
@click.option("--http-path", default=None, help="Override HTTP path")
@click.option("--http-body", default=None, help="Override HTTP request body")
@click.option("--syn-spoof-src", default=None, help="SYN source spoofing: random or IPv4 CIDR")
@click.option("--ramp-start", "ramp_start", default=None, type=int, help="Ramp-up: starting rps")
@click.option("--ramp-end", "ramp_end", default=None, type=int, help="Ramp-up: ending rps")
@click.option("--ramp-steps", "ramp_steps", default=5, type=int, help="Number of ramp levels (default 5)")
@click.option("--json", "as_json", is_flag=True, help="Emit a machine-readable JSON result instead of the human summary")
@click.option("--quiet", "-q", is_flag=True, help="Suppress live pps output")
def run(
    config_path: str | None,
    target: str | None,
    host: str | None,
    port: int | None,
    attack: str | None,
    duration: float | None,
    rps: int | None,
    workers: int | None,
    udp_size: int | None,
    udp_fill: str | None,
    tcp_ports: str | None,
    http_method: str | None,
    http_path: str | None,
    http_body: str | None,
    syn_spoof_src: str | None,
    ramp_start: int | None,
    ramp_end: int | None,
    ramp_steps: int,
    as_json: bool,
    quiet: bool,
) -> None:
    """Run a flood against the configured target.

    Ramp-up example:  ddos run -c cfg.yaml --ramp-start 1000 --ramp-end 20000 --ramp-steps 8
    """
    from .config import Ramp

    try:
        data = load_yaml(Path(config_path)) if config_path else {}
    except (OSError, ValueError) as exc:
        raise click.ClickException(f"could not load config: {exc}") from exc
    if target is not None and host is not None:
        raise click.UsageError("--target and --host are mutually exclusive")
    if target is not None:
        data["target"] = target
    selected_attack = attack or data.get("attack")
    if tcp_ports is not None and selected_attack != "tcp":
        raise click.UsageError("--tcp-ports is only valid with --attack tcp")
    if any(v is not None for v in (udp_size, udp_fill)) and selected_attack != "udp":
        raise click.UsageError("--udp-size/--udp-fill are only valid with --attack udp")
    if any(v is not None for v in (http_method, http_path, http_body)) and selected_attack != "http":
        raise click.UsageError("--http-* options are only valid with --attack http")
    if syn_spoof_src is not None and selected_attack != "syn":
        raise click.UsageError("--syn-spoof-src is only valid with --attack syn")
    if host is not None:
        if port is None and ":" not in host.rsplit("/", 1)[-1] and selected_attack in ("tcp", "udp", "syn"):
            raise click.UsageError("--host for TCP/UDP/SYN must be used with --port")
        data["target"] = f"{host}:{port}" if port is not None else host
    elif port is not None:
        raise click.UsageError("--port requires --host")
    if attack is not None:
        data["attack"] = attack
    if not data.get("target") or not data.get("attack"):
        raise click.UsageError("provide --config, or both --target and --attack")
    if duration is not None:
        data["duration_sec"] = duration
    if rps is not None and ramp_start is None:
        data.setdefault("rate", {})["rps"] = rps
    if workers is not None:
        data["workers"] = workers
    if udp_size is not None or udp_fill is not None:
        data.setdefault("udp", {})
        if udp_size is not None:
            data["udp"]["size"] = udp_size
        if udp_fill is not None:
            data["udp"]["fill"] = udp_fill
    if tcp_ports is not None:
        data.setdefault("tcp", {})["ports"] = _parse_ports(tcp_ports)
    if any(v is not None for v in (http_method, http_path, http_body)):
        data.setdefault("http", {})
        if http_method is not None:
            data["http"]["method"] = http_method
        if http_path is not None:
            data["http"]["path"] = http_path
        if http_body is not None:
            data["http"]["body"] = http_body
    if syn_spoof_src is not None:
        data.setdefault("syn", {})["spoof_src"] = syn_spoof_src
    # CLI ramp overrides any YAML ramp.
    if ramp_start is not None or ramp_end is not None:
        base = (data.get("rate") or {}).get("rps", 10_000)
        data["ramp"] = {
            "start_rps": ramp_start or base,
            "end_rps": ramp_end or max(base * 4, ramp_start or base),
            "steps": ramp_steps,
        }
    try:
        cfg = Config(**data)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

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
    # With --json, keep stdout pure JSON: header + live ticker go to stderr.
    click.echo(
        f"→ {cfg.attack} flood → {cfg.target} {label} × {cfg.duration_sec}s",
        err=as_json,
    )
    asyncio.run(go())
    report(engine.stats, cfg.duration_sec, ramp_steps=ramp_steps_table or None, cfg=cfg, as_json=as_json)


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
        try:
            if "-" in part:
                lo, hi = part.split("-", 1)
                lo_i, hi_i = int(lo), int(hi)
                if not (1 <= lo_i <= hi_i <= 65_535):
                    raise ValueError
                out.update(range(lo_i, hi_i + 1))
            elif part:
                port = int(part)
                if not 1 <= port <= 65_535:
                    raise ValueError
                out.add(port)
        except ValueError as exc:
            raise click.BadParameter(f"invalid port specification: {part!r}") from exc
    if not out:
        raise click.BadParameter("at least one port is required")
    return sorted(out)


if __name__ == "__main__":
    main()
