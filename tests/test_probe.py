from __future__ import annotations

import asyncio

from ddos_tool.cli import _parse_ports
from ddos_tool.probe import ScanReport, scan


def test_parse_ports_single() -> None:
    assert _parse_ports("80") == [80]


def test_parse_ports_list() -> None:
    assert _parse_ports("80,443,8080") == [80, 443, 8080]


def test_parse_ports_range() -> None:
    assert _parse_ports("1-5") == [1, 2, 3, 4, 5]


def test_parse_ports_mixed() -> None:
    assert _parse_ports("80,443-445,9000") == [80, 443, 444, 445, 9000]


def test_scan_report_classification() -> None:
    rep = ScanReport(host="x")
    from ddos_tool.probe import PortResult

    rep.results = [
        PortResult(80, "open", rtt_ms=1.0),
        PortResult(443, "closed"),
        PortResult(9999, "filtered"),
    ]
    assert [r.port for r in rep.open] == [80]
    assert [r.port for r in rep.closed] == [443]
    assert [r.port for r in rep.filtered] == [9999]


def test_scan_localhost() -> None:
    """Scan a tiny range on localhost; port 22 or something should be classified."""

    async def go():
        return await scan("127.0.0.1", range(1, 5), concurrency=4, timeout=0.5, data_probe=False)

    rep = asyncio.run(go())
    # All four ports should have a classification (no crash).
    assert len(rep.results) == 4
    statuses = {r.status for r in rep.results}
    assert statuses <= {"open", "closed", "filtered"}
