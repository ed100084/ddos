from __future__ import annotations

import asyncio
import ssl

from ..config import Config
from .base import AttackEngine


class TlsHandshakeFlood(AttackEngine):
    """Controlled TLS handshake load: connect, complete handshake, then close."""

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg.effective_rps(), cfg.workers, cfg.duration_sec)
        host, _, port_s = cfg.target.rpartition(":")
        self.host = host
        self.port = int(port_s or 443)
        self.ssl_context = ssl.create_default_context()
        # Load tests commonly target test/self-signed certificates.
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    async def run(self) -> None:
        timeout = 10.0

        async def worker() -> None:
            while True:
                await self.bucket.acquire()
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            self.host,
                            self.port,
                            ssl=self.ssl_context,
                            server_hostname=self.host,
                        ),
                        timeout=timeout,
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
        await asyncio.sleep(self.duration_sec)
        for worker_task in workers:
            worker_task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
