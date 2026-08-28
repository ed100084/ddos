from __future__ import annotations

import pytest

pytest.importorskip("scapy")

from ddos_tool.config import Config, Rate, SynPayload
from ddos_tool.engine.syn_flood import SynFlood


def test_syn_engine_initializes_ack_counter() -> None:
    engine = SynFlood(Config(target="127.0.0.1:8443", attack="syn", rate=Rate(rps=10), syn=SynPayload()))
    assert engine.stats["acked"] == 0
