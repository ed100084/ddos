from __future__ import annotations

import asyncio

from ..config import Config, TcpPayload
from .base import AttackEngine


class TcpConnectFlood(AttackEngine):
    """L4 TCP connect flood: workers repeatedly open+close connections at a target rate.

    Measures how well the target's SYN proxy / connection table copes. A handshake
    (SYN-ACK) counts as ok even if the peer RSTs right after — that is exactly the
    firewall behavior we want to stress on 203.0.113.17.
    """

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg.effective_rps(), cfg.workers, cfg.duration_sec)
        payload = cfg.tcp or TcpPayload()
        host, _, port_s = cfg.target.partition(":")
        self.host = host
        default_port = int(port_s or 80)
        # Optional multi-port: workers round-robin across the list.
        self.ports = tuple(payload.ports) if payload.ports else (default_port,)

    async def run(self) -> None:
        timeout = 3.0
        next_port = 0
        port_lock = asyncio.Lock()

        async def worker() -> None:
            nonlocal next_port
            while not self.stop_event.is_set():
                await self.bucket.acquire()
                async with port_lock:
                    port = self.ports[next_port % len(self.ports)]
                    next_port += 1
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.host, port), timeout=timeout
                    )
                    self.stats["ok"] += 1
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (OSError, ConnectionResetError):
                        pass
                except (OSError, asyncio.TimeoutError):
                    self.stats["err"] += 1
                finally:
                    self.stats["sent"] += 1

        workers = [asyncio.create_task(worker()) for _ in range(self.workers)]
        try:
            await asyncio.wait_for(self.stop_event.wait(), timeout=self.duration_sec)
        except asyncio.TimeoutError:
            pass
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
