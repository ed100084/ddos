"""Local dev target for ddos-tool — an aiohttp counter endpoint + UDP sink.

Run:  python scripts/dev_server.py --port 8099 --udp-port 9999
Then: ddos run -c config/example.yaml
"""
from __future__ import annotations

import argparse
import asyncio

import aiohttp
from aiohttp import web


def make_app() -> web.Application:
    app = web.Application()
    app["count"] = 0

    async def index(request: web.Request) -> web.Response:
        app["count"] += 1
        return web.json_response({"ok": True, "n": app["count"]})

    async def stats(request: web.Request) -> web.Response:
        return web.json_response({"requests": app["count"]})

    app.router.add_get("/", index)
    app.router.add_get("/stats", stats)
    return app


class UdpSink(asyncio.DatagramProtocol):
    def __init__(self, counter: dict[str, int]) -> None:
        self.counter = counter

    def datagram_received(self, data: bytes, addr) -> None:
        self.counter["packets"] += 1
        self.counter["bytes"] += len(data)


async def run_udp(port: int, counter: dict[str, int], stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()

    async def _serve() -> None:
        transport, _ = await loop.create_datagram_endpoint(lambda: UdpSink(counter), local_addr=("127.0.0.1", port))
        try:
            await stop.wait()
        finally:
            transport.close()

    task = asyncio.create_task(_serve())
    return task


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--udp-port", type=int, default=9999)
    args = ap.parse_args()

    app = make_app()
    udp_counter: dict[str, int] = {"packets": 0, "bytes": 0}
    stop = asyncio.Event()

    async def serve() -> None:
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", args.port)
        await site.start()
        udp_task = await run_udp(args.udp_port, udp_counter, stop)
        print(f"HTTP target  → http://127.0.0.1:{args.port}/   (stats: /stats)")
        print(f"UDP sink     → 127.0.0.1:{args.udp_port}")
        try:
            while True:
                await asyncio.sleep(1)
                print(f"\r  http={app['count']}  udp_pkts={udp_counter['packets']}", end="", flush=True)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            stop.set()
            await runner.cleanup()
            udp_task.cancel()

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
