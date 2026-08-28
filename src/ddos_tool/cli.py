from __future__ import annotations

import asyncio
import time
from pathlib import Path

import click
import yaml

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
    if cfg.attack == "tls":
        from .engine.tls_flood import TlsHandshakeFlood

        return TlsHandshakeFlood(cfg)
    if cfg.attack == "syn":
        from .engine.syn_flood import SynFlood  # lazy: scapy is optional

        return SynFlood(cfg)
    raise click.ClickException(f"unknown attack type: {cfg.attack}")


@click.group(context_settings={"max_content_width": 110})
def main() -> None:
    """ddos-tool — single-host traffic simulator for authorized load testing.

    Use only against systems you own or have explicit permission to test.
    """


@main.command()
@click.option("--config", "-c", "config_path", required=False, type=click.Path(exists=True), help="YAML config; CLI options override it")
@click.option("--target", default=None, help="HTTP URL or legacy host:port target")
@click.option("--host", default=None, help="IPv4 hostname/IP (with --port for TCP, UDP, or SYN)")
@click.option("--port", type=int, default=None, help="Single destination port used with --host")
@click.option("--attack", type=click.Choice(["http", "udp", "tcp", "tls", "syn"]), default=None, help="Traffic engine to run")
@click.option("--duration", "-d", default=None, type=float, help="Run duration in seconds (overrides YAML)")
@click.option("--rps", default=None, type=int, help="Target operations/second; ignored when --ramp-start is set")
@click.option("--workers", default=None, type=int, help="Number of concurrent workers")
@click.option("--udp-size", default=None, type=int, help="UDP payload size in bytes")
@click.option("--udp-fill", default=None, help="UDP payload fill string")
@click.option("--tcp-ports", default=None, help="TCP destination ports, e.g. 80,8080")
@click.option("--http-method", default=None, help="HTTP method, e.g. GET or POST")
@click.option("--http-path", default=None, help="HTTP request path")
@click.option("--http-body", default=None, help="HTTP request body")
@click.option("--syn-spoof-src", default=None, help="Opt-in SYN spoofing: random or IPv4 CIDR")
@click.option("--ramp-start", "ramp_start", default=None, type=int, help="Ramp starting RPS")
@click.option("--ramp-end", "ramp_end", default=None, type=int, help="Ramp ending RPS")
@click.option("--ramp-steps", "ramp_steps", default=5, type=int, help="Number of ramp levels")
@click.option("--find-limit", is_flag=True, help="Stop after two consecutive high-error ramp steps")
@click.option("--err-threshold", type=float, default=5.0, show_default=True, help="Error percentage considered failing")
@click.option("--max-rps", type=int, default=None, help="Safety cap for ramp end rate")
@click.option("--json", "as_json", is_flag=True, help="Print only the final machine-readable JSON to stdout")
@click.option("--quiet", "-q", is_flag=True, help="Suppress live rate output on stderr")
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
    find_limit: bool,
    err_threshold: float,
    max_rps: int | None,
    as_json: bool,
    quiet: bool,
) -> None:
    """Run an authorized traffic simulation.

    Configuration can come from YAML, CLI flags, or both. CLI values override YAML.
    For HTTP use --target with a full URL. For TCP/UDP/SYN use --host and --port.

    Examples:
      ddos run --host 127.0.0.1 --port 9999 --attack udp --rps 2000
      ddos run --target http://127.0.0.1:8099/ --attack http --duration 10
      ddos run -c config.yaml --ramp-start 500 --ramp-end 6000 --ramp-steps 6
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
        if port is None and ":" not in host.rsplit("/", 1)[-1] and selected_attack in ("tcp", "udp", "tls", "syn"):
            raise click.UsageError("--host for TCP/UDP/TLS/SYN must be used with --port")
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
    if find_limit and not (ramp_start is not None or ramp_end is not None or data.get("ramp")):
        base = (data.get("rate") or {}).get("rps", 10_000)
        data["ramp"] = {"start_rps": base, "end_rps": max_rps or base * 4, "steps": ramp_steps}
    if max_rps is not None and data.get("ramp"):
        data["ramp"]["end_rps"] = min(data["ramp"]["end_rps"], max_rps)
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
                asyncio.create_task(_ramp_controller(engine, cfg, ramp_steps_table, find_limit, err_threshold))
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
    report(engine.stats, cfg.duration_sec, ramp_steps=ramp_steps_table or None, cfg=cfg,
           as_json=as_json, breaking_rps=engine.breaking_rps)


async def _ramp_controller(
    engine, cfg: Config, steps_table: list[tuple[int, int, int, int]] | None = None,
    find_limit: bool = False, err_threshold: float = 5.0,
) -> None:
    """Step the engine's token bucket from ramp.start_rps to ramp.end_rps.

    If `steps_table` is provided, append (step_index, rate, ops_in_step, errs_in_step)
    rows so the reporter can show which level started erroring.
    """
    rates = cfg.ramp.rates()
    step_dur = cfg.duration_sec / len(rates)
    prev_sent = prev_err = 0
    consecutive_failures = 0
    for i, r in enumerate(rates):
        engine.bucket.set_rate(r)
        await asyncio.sleep(step_dur)
        if steps_table is not None:
            sent_now = int(engine.stats.get("sent", 0))
            err_now = int(engine.stats.get("err", 0))
            steps_table.append((i + 1, r, sent_now - prev_sent, err_now - prev_err))
            ops = sent_now - prev_sent
            errs = err_now - prev_err
            if find_limit and ops and errs / ops * 100 >= err_threshold:
                consecutive_failures += 1
            else:
                consecutive_failures = 0
            if find_limit and consecutive_failures >= 2:
                engine.breaking_rps = rates[i - 2] if i >= 2 else rates[0]
                engine.stop()
                return
            prev_sent, prev_err = sent_now, err_now


@main.command()
@click.argument("host")
@click.option("--ports", "-p", default="1-65535", help="Port range or list: 80,443 / 1-1024 / 80,443,8080")
@click.option("--concurrency", "-c", default=2000, type=int, help="Parallel connections")
@click.option("--timeout", "-t", default=1.0, type=float, help="Per-port timeout (s)")
@click.option("--no-data-probe", is_flag=True, help="Skip the RST-after-data check on open ports")
@click.option("--emit-config", type=click.Path(), default=None, help="Write a runnable TCP config YAML from open ports")
def probe(host: str, ports: str, concurrency: int, timeout: float, no_data_probe: bool, emit_config: str | None) -> None:
    """Scan TCP ports and classify them as open, closed, or filtered.

    Open ports are data-probed by default to detect immediate RST-after-data
    behavior commonly produced by firewalls and middleboxes.
    """
    from .probe import format_report, scan

    port_list = _parse_ports(ports)
    click.echo(f"→ probing {host} ports [{ports}] ({len(port_list)} ports, concurrency={concurrency})")
    t0 = time.monotonic()
    rep = asyncio.run(scan(host, port_list, concurrency=concurrency, timeout=timeout, data_probe=not no_data_probe))
    click.echo(format_report(rep, time.monotonic() - t0))
    if emit_config:
        open_ports = [result.port for result in rep.open]
        selected_ports = open_ports or [80]
        output = Path(emit_config)
        output.parent.mkdir(parents=True, exist_ok=True)
        config = {
            "target": f"{host}:{selected_ports[0]}",
            "attack": "tcp",
            "duration_sec": 30,
            "rate": {"rps": 1000},
            "workers": 8,
            "tcp": {"ports": selected_ports},
        }
        output.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        click.echo(f"wrote config: {output}")


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
