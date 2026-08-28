from __future__ import annotations

import asyncio

from ddos_tool.config import Config, Rate, UdpPayload
from ddos_tool.engine.udp_flood import UdpFlood


def test_udp_flood_end_to_end() -> None:
    async def go():
        received = 0
        payloads: list[bytes] = []

        class Sink(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                nonlocal received
                received += 1
                payloads.append(data)

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            Sink, local_addr=("127.0.0.1", 0)
        )
        port = transport.get_extra_info("sockname")[1]
        cfg = Config(
            target=f"127.0.0.1:{port}", attack="udp", duration_sec=0.2,
            rate=Rate(rps=200), workers=2, udp=UdpPayload(size=16, fill="random"),
        )
        engine = UdpFlood(cfg)
        try:
            await engine.run()
            await asyncio.sleep(0.05)
        finally:
            transport.close()
        return engine.stats, received, payloads

    stats, received, payloads = asyncio.run(go())
    assert stats["sent"] >= 20
    assert stats["ok"] == stats["sent"]
    assert received >= stats["sent"] * 0.8
    assert len(set(payloads)) > 1
