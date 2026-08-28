from __future__ import annotations

import asyncio

from ..config import Config, UdpPayload
from .base import AttackEngine


class UdpFlood(AttackEngine):
    """L4 flood: N senders firing fixed-size datagrams at host:port."""

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg.rate.rps, cfg.workers, cfg.duration_sec)
        payload = cfg.udp or UdpPayload()
        self.payload = payload.encoded()
        host, _, port_s = cfg.target.partition(":")
        self.host = host
        self.port = int(port_s or 9999)

    async def run(self) -> None:
        loop = asyncio.get_running_loop()

        async def worker() -> None:
            while True:
                await self.bucket.acquire()
                try:
                    transport, _ = await loop.create_datagram_endpoint(
                        lambda: _UdpReceiver(), remote_addr=(self.host, self.port)
                    )
                    transport.sendto(self.payload)
                    transport.close()
                    self.stats["ok"] += 1
                except OSError:
                    self.stats["err"] += 1
                finally:
                    self.stats["sent"] += 1

        workers = [asyncio.create_task(worker()) for _ in range(self.workers)]
        await asyncio.sleep(self.duration_sec)
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)


class _UdpReceiver(asyncio.DatagramProtocol):
    """Minimal protocol so create_datagram_endpoint has a callback; we only send."""

    def datagram_received(self, data, addr) -> None:  # pragma: no cover - rarely used
        pass
