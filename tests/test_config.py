from __future__ import annotations

import asyncio

import pytest

from ddos_tool.config import Config, Rate, SynPayload, UdpPayload, load_yaml


def test_config_defaults() -> None:
    cfg = Config(target="http://127.0.0.1:8099/", attack="http")
    assert cfg.rate.rps == 10_000
    assert cfg.workers == 8
    assert cfg.duration_sec == 60


def test_config_http_requires_url() -> None:
    with pytest.raises(ValueError):
        Config(target="example.com", attack="http")


def test_config_udp_requires_host_port() -> None:
    with pytest.raises(ValueError):
        Config(target="127.0.0.1", attack="udp")
    cfg = Config(target="127.0.0.1:9999", attack="udp")
    assert cfg.attack == "udp"


def test_config_tcp_requires_host_port() -> None:
    with pytest.raises(ValueError):
        Config(target="127.0.0.1", attack="tcp")
    from ddos_tool.config import TcpPayload

    cfg = Config(
        target="127.0.0.1:80",
        attack="tcp",
        tcp=TcpPayload(ports=[80, 8080]),
    )
    assert cfg.attack == "tcp"
    assert cfg.tcp.ports == [80, 8080]


def test_config_syn_requires_supported_ipv4_host_port() -> None:
    with pytest.raises(ValueError):
        Config(target="127.0.0.1", attack="syn")
    with pytest.raises(ValueError, match="IPv6"):
        Config(target="[::1]:80", attack="syn")


def test_config_tls_requires_host_port() -> None:
    cfg = Config(target="127.0.0.1:443", attack="tls")
    assert cfg.attack == "tls"
    with pytest.raises(ValueError):
        Config(target="127.0.0.1", attack="tls")


def test_tcp_payload_port_range() -> None:
    from ddos_tool.config import TcpPayload

    with pytest.raises(ValueError):
        TcpPayload(ports=[70_000])


def test_syn_spoof_source_is_opt_in_and_validated() -> None:
    assert SynPayload().spoof_src is None
    assert SynPayload(spoof_src="random").spoof_src == "random"
    assert SynPayload(spoof_src="10.0.0.0/8").spoof_src == "10.0.0.0/8"
    with pytest.raises(ValueError):
        SynPayload(spoof_src="2001:db8::/32")


def test_ramp_rates_linear() -> None:
    from ddos_tool.config import Ramp

    r = Ramp(start_rps=1000, end_rps=5000, steps=5)
    assert r.rates() == [1000, 2000, 3000, 4000, 5000]


def test_ramp_rates_single_step() -> None:
    from ddos_tool.config import Ramp

    assert Ramp(start_rps=100, end_rps=900, steps=1).rates() == [900]


def test_config_effective_rps() -> None:
    from ddos_tool.config import Ramp

    flat = Config(target="http://x/", attack="http")
    assert flat.effective_rps() == 10_000
    ramped = Config(
        target="http://x/", attack="http", rate=Rate(rps=999), ramp=Ramp(start_rps=50, end_rps=500)
    )
    assert ramped.effective_rps() == 50


def test_udp_payload_encoding() -> None:
    p = UdpPayload(size=10, fill="ab")
    assert len(p.encoded()) == 10
    assert p.encoded() == b"ababababab"


def test_load_yaml(tmp_path) -> None:
    f = tmp_path / "c.yaml"
    f.write_text("target: http://x/\nattack: http\nrate:\n  rps: 42\n")
    data = load_yaml(f)
    cfg = Config(**data)
    assert cfg.rate.rps == 42


def test_token_bucket_pacing() -> None:
    from ddos_tool.engine.base import TokenBucket

    async def go():
        b = TokenBucket(rate=1000)
        import time

        t0 = time.monotonic()
        for _ in range(50):
            await b.acquire()
        return (time.monotonic() - t0) * 1000

    ms = asyncio.run(go())
    # 50 ops @ 1000/s ≈ 50ms; allow generous slack for CI.
    assert ms < 300, f"token bucket too slow: {ms:.0f}ms"
