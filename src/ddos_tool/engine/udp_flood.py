from __future__ import annotations

import asyncio

from ..config import Config, UdpPayload
from .base import AttackEngine


class UdpFlood(AttackEngine):
    """L4 flood: N senders firing fixed-size datagrams at host:port."""

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg.effective_rps(), cfg.workers, cfg.duration_sec)
        payload = cfg.udp or UdpPayload()
        self.payload = payload.encoded() if payload.fill != "random" else None
        self._payload_config = payload
        host, _, port_s = cfg.target.partition(":")
        self.host = host
        self.port = int(port_s or 9999)

    async def run(self) -> None:
        loop = asyncio.get_running_loop()

        async def worker() -> None:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UdpReceiver(), remote_addr=(self.host, self.port)
            )
            try:
                while not self.stop_event.is_set():
                    await self.bucket.acquire()
                    payload = self.payload if self.payload is not None else self._payload_config.encoded()
                    transport.sendto(payload)
                    self.stats["ok"] += 1
                    self.stats["sent"] += 1
            except OSError:
                # A transport-level failure ends this worker; operations already
                # sent remain counted and the failed send is recorded once.
                self.stats["err"] += 1
                self.stats["sent"] += 1
            finally:
                transport.close()

        workers = [asyncio.create_task(worker()) for _ in range(self.workers)]
        try:
            await asyncio.wait_for(self.stop_event.wait(), timeout=self.duration_sec)
        except asyncio.TimeoutError:
            pass
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)


class _UdpReceiver(asyncio.DatagramProtocol):
    """Minimal protocol so create_datagram_endpoint has a callback; we only send."""

    def datagram_received(self, data, addr) -> None:  # pragma: no cover - rarely used
        pass
