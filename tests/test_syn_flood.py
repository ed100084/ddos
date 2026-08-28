from __future__ import annotations

import pytest

pytest.importorskip("scapy")

from ddos_tool.config import Config, Rate, SynPayload
from ddos_tool.engine.syn_flood import SynFlood


def test_syn_engine_filters_ack_by_source_port() -> None:
    from scapy.all import IP, TCP

    sent = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=40000, dport=8443, flags="S")
    own_ack = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=8443, dport=40000, flags="SA")
    other_ack = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=8443, dport=40001, flags="SA")
    answered = [(sent, own_ack), (sent, other_ack)]
    assert sum(
        1 for sent_packet, reply in answered
        if reply.haslayer(TCP)
        and reply[TCP].dport == sent_packet[TCP].sport
        and (int(reply[TCP].flags) & 0x12) == 0x12
    ) == 1


def test_syn_engine_initializes_ack_counter() -> None:
    engine = SynFlood(Config(target="127.0.0.1:8443", attack="syn", rate=Rate(rps=10), syn=SynPayload()))
    assert engine.stats["acked"] == 0
