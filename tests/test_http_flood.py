from __future__ import annotations

import asyncio

from aiohttp import web

from ddos_tool.config import Config, HttpPayload, Rate
from ddos_tool.engine.http_flood import HttpFlood


def test_http_flood_end_to_end() -> None:
    async def go():
        app = web.Application()
        count = 0

        async def index(request: web.Request) -> web.Response:
            nonlocal count
            count += 1
            return web.json_response({"ok": True})

        app.router.add_get("/", index)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 8199)
        await site.start()

        cfg = Config(
            target="http://127.0.0.1:8199/",
            attack="http",
            duration_sec=2,
            rate=Rate(rps=500),
            workers=8,
            http=HttpPayload(method="GET", path="/"),
        )
        engine = HttpFlood(cfg)
        try:
            await engine.run()
        finally:
            await runner.cleanup()
        return engine.stats, count

    stats, server_count = asyncio.run(go())

    sent = stats["sent"]
    ok = stats["ok"]
    assert sent >= 400, f"expected ~1000 ops in 2s @500rps, got {sent}"
    assert ok / sent > 0.95, f"too many errors: {stats['err']}/{sent}"
    # Server should have seen roughly the same number of requests.
    assert server_count >= sent * 0.9
