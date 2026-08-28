"""TCP connect scanner — classifies ports as open / closed(RST at SYN) / filtered(timeout).

For open ports it optionally sends one byte to detect the "RST-after-data" pattern
(firewall/middlebox signature seen on 222.179.105.17:80/8080).
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class PortResult:
    port: int
    status: str  # open | closed | filtered
    rtt_ms: float = 0.0
    rst_on_data: bool | None = None  # only set for open ports when data-probed


@dataclass
class ScanReport:
    host: str
    results: list[PortResult] = field(default_factory=list)

    @property
    def open(self) -> list[PortResult]:
        return [r for r in self.results if r.status == "open"]

    @property
    def closed(self) -> list[PortResult]:
        return [r for r in self.results if r.status == "closed"]

    @property
    def filtered(self) -> list[PortResult]:
        return [r for r in self.results if r.status == "filtered"]


async def _probe_port(
    host: str, port: int, timeout: float, data_probe: bool, sem: asyncio.Semaphore
) -> PortResult:
    async with sem:
        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        except (ConnectionRefusedError, OSError):
            return PortResult(port, "closed")
        except (asyncio.TimeoutError, TimeoutError):
            return PortResult(port, "filtered", rtt_ms=(time.monotonic() - t0) * 1000)

        rtt = (time.monotonic() - t0) * 1000
        result = PortResult(port, "open", rtt_ms=rtt)

        if data_probe:
            try:
                writer.write(b"X")
                await writer.drain()
                # Wait briefly for a reply or RST.
                try:
                    chunk = await asyncio.wait_for(reader.read(1), timeout=0.75)
                    result.rst_on_data = chunk == b""  # EOF (FIN) vs data; RST surfaces as error below
                except (asyncio.TimeoutError, TimeoutError):
                    result.rst_on_data = False  # held open — real service
            except (ConnectionResetError, OSError):
                result.rst_on_data = True
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ConnectionResetError):
                    pass
        else:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionResetError):
                pass
        return result


async def scan(
    host: str,
    ports: range | list[int],
    concurrency: int = 2000,
    timeout: float = 1.0,
    data_probe: bool = True,
) -> ScanReport:
    sem = asyncio.Semaphore(concurrency)
    report = ScanReport(host=host)
    tasks = [
        _probe_port(host, p, timeout, data_probe, sem) for p in ports
    ]
    done = 0
    total = len(tasks)
    for fut in asyncio.as_completed(tasks):
        r = await fut
        report.results.append(r)
        done += 1
        if done % 5000 == 0:
            print(f"\r  scanned {done}/{total}", end="", flush=True)
    if total:
        print(f"\r  scanned {total}/{total}  ", end="", flush=True)
    report.results.sort(key=lambda r: r.port)
    return report


def format_report(rep: ScanReport, elapsed: float) -> str:
    lines = [
        f"── probe {rep.host} ─────────────────────",
        f"  duration : {elapsed:.1f}s",
        f"  open     : {len(rep.open)}   closed(RST@SYN): {len(rep.closed)}   filtered(timeout): {len(rep.filtered)}",
    ]
    if rep.open:
        lines.append("  open ports:")
        for r in rep.open:
            extra = ""
            if r.rst_on_data is True:
                extra = "  ⚠ RST-after-data (firewall/middlebox?)"
            elif r.rst_on_data is False:
                extra = "  ✓ holds connection"
            lines.append(f"    {r.port:<6} {r.rtt_ms:7.1f} ms{extra}")
    return "\n".join(lines)
