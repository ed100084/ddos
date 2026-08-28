from __future__ import annotations

import pytest

dpkt = pytest.importorskip("dpkt")

from ddos_tool.config import Config, ReplayPayload
from ddos_tool.engine.replay import PcapReplay


def test_replay_reads_udp_payloads(tmp_path) -> None:
    path = tmp_path / "sample.pcap"
    with path.open("wb") as stream:
        writer = dpkt.pcap.Writer(stream)
        for timestamp, payload in ((1.0, b"one"), (1.5, b"two")):
            udp = dpkt.udp.UDP(sport=1000, dport=9999, data=payload)
            udp.ulen = len(udp)
            ip = dpkt.ip.IP(src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x01", p=dpkt.ip.IP_PROTO_UDP, data=udp)
            ip.len = len(ip)
            frame = dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
            writer.writepkt(bytes(frame), ts=timestamp)
        writer.close()
    cfg = Config(target="127.0.0.1:9999", attack="replay", replay=ReplayPayload(file=str(path)))
    assert [payload for _, payload in PcapReplay(cfg)._payloads()] == [b"one", b"two"]
