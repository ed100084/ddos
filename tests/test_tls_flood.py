from __future__ import annotations

import asyncio

from ddos_tool.config import Config, Rate
from ddos_tool.engine.tls_flood import TlsHandshakeFlood


class _Writer:
    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


def test_tls_handshake_engine_success(monkeypatch) -> None:
    calls = []

    async def fake_open_connection(*args, **kwargs):
        calls.append(kwargs)
        return object(), _Writer()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    cfg = Config(target="127.0.0.1:443", attack="tls", duration_sec=0.05, rate=Rate(rps=20), workers=1)
    engine = TlsHandshakeFlood(cfg)
    asyncio.run(engine.run())

    assert engine.stats["sent"] >= 1
    assert engine.stats["ok"] == engine.stats["sent"]
    assert calls and calls[0]["ssl"] is engine.ssl_context
    assert calls[0]["server_hostname"] == "127.0.0.1"


def test_tls_handshake_engine_errors_are_counted(monkeypatch) -> None:
    async def fake_open_connection(*args, **kwargs):
        raise OSError("connection failed")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    cfg = Config(target="127.0.0.1:443", attack="tls", duration_sec=0.05, rate=Rate(rps=20), workers=1)
    engine = TlsHandshakeFlood(cfg)
    asyncio.run(engine.run())

    assert engine.stats["sent"] >= 1
    assert engine.stats["err"] == engine.stats["sent"]
