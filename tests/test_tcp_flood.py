from __future__ import annotations

import asyncio

from ddos_tool.config import Config, Rate, TcpPayload
from ddos_tool.engine.tcp_flood import TcpConnectFlood


def test_tcp_connect_flood_end_to_end() -> None:
    async def go():
        accepted = 0

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            nonlocal accepted
            accepted += 1
            try:
                await reader.read(1)  # drain whatever the client sends (nothing in MVP)
            except (ConnectionResetError, OSError):
                pass
            finally:
                writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 8299)

        cfg = Config(
            target="127.0.0.1:8299",
            attack="tcp",
            duration_sec=2,
            rate=Rate(rps=500),
            workers=8,
            tcp=TcpPayload(),
        )
        engine = TcpConnectFlood(cfg)
        try:
            await engine.run()
        finally:
            server.close()
            await server.wait_closed()
        return engine.stats, accepted

    stats, accepted = asyncio.run(go())

    sent = stats["sent"]
    ok = stats["ok"]
    assert sent >= 400, f"expected ~1000 connects in 2s @500rps, got {sent}"
    assert ok / sent > 0.95, f"too many errors: {stats['err']}/{sent}"
    # Server should have accepted roughly the same number of connections.
    assert accepted >= sent * 0.8


def test_tcp_connect_flood_multi_port() -> None:
    async def go():
        counts: dict[int, int] = {}

        def make_handler(port: int):
            async def handle(reader, writer):
                counts[port] = counts.get(port, 0) + 1
                writer.close()

            return handle

        servers = [
            await asyncio.start_server(make_handler(p), "127.0.0.1", p) for p in (8399, 8400)
        ]

        cfg = Config(
            target="127.0.0.1:8399",
            attack="tcp",
            duration_sec=1,
            rate=Rate(rps=200),
            workers=4,
            tcp=TcpPayload(ports=[8399, 8400]),
        )
        engine = TcpConnectFlood(cfg)
        try:
            await engine.run()
        finally:
            for s in servers:
                s.close()
                await s.wait_closed()
        return engine.stats, counts

    stats, counts = asyncio.run(go())
    # Both ports should have received some connections (round-robin).
    assert counts.get(8399, 0) > 0 and counts.get(8400, 0) > 0, f"counts={counts}"
    assert stats["sent"] >= 100


def test_tcp_connect_flood_ramp_up() -> None:
    """Ramp from low to high rps; total should land between flat-low and flat-high."""

    async def go():
        accepted = 0

        async def handle(reader, writer):
            nonlocal accepted
            accepted += 1
            try:
                await reader.read(1)
            except (ConnectionResetError, OSError):
                pass
            finally:
                writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 8499)

        from ddos_tool.config import Ramp

        cfg = Config(
            target="127.0.0.1:8499",
            attack="tcp",
            duration_sec=3,
            rate=Rate(rps=50),
            workers=8,
            tcp=TcpPayload(),
            ramp=Ramp(start_rps=100, end_rps=600, steps=3),
        )
        engine = TcpConnectFlood(cfg)

        async def ramp_controller():
            rates = cfg.ramp.rates()  # [100, 350, 600]
            step_dur = cfg.duration_sec / len(rates)
            for i, r in enumerate(rates):
                if i > 0:
                    await asyncio.sleep(step_dur)
                engine.bucket.set_rate(r)

        ramp_task = asyncio.create_task(ramp_controller())
        try:
            await engine.run()
        finally:
            ramp_task.cancel()
            server.close()
            await server.wait_closed()
        return engine.stats, accepted

    stats, _ = asyncio.run(go())
    # 3s averaging ~350 rps => roughly 1000 ops; allow a wide band.
    assert 600 <= stats["sent"] <= 2200, f"ramp total out of range: {stats['sent']}"
