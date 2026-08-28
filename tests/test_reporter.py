from __future__ import annotations

import json

from ddos_tool.config import Config, Ramp, Rate
from ddos_tool.reporter import build_result


def test_build_result_flat() -> None:
    cfg = Config(target="http://x/", attack="http", rate=Rate(rps=100), workers=4)
    res = build_result(cfg, {"sent": 1000, "ok": 980, "err": 20}, duration_sec=5.0)
    assert res["attack"] == "http"
    assert res["stats"]["sent"] == 1000
    assert res["stats"]["err_pct"] == 2.0
    assert res["ramp"] is None
    assert res["per_step"] is None


def test_build_result_ramped() -> None:
    cfg = Config(
        target="x:80", attack="tcp", rate=Rate(rps=10), workers=4,
        ramp=Ramp(start_rps=100, end_rps=300, steps=2),
    )
    res = build_result(cfg, {"sent": 400, "ok": 380, "err": 20}, duration_sec=2.0,
                       ramp_steps=[(1, 100, 200, 0), (2, 300, 200, 20)])
    assert res["ramp"] == {"start_rps": 100, "end_rps": 300}
    assert len(res["per_step"]) == 2
    assert res["per_step"][1]["err_pct"] == 10.0


def test_build_result_is_json_serializable() -> None:
    cfg = Config(target="x:80", attack="tcp")
    res = build_result(cfg, {"sent": 10, "ok": 9, "err": 1}, duration_sec=1.0)
    # Round-trips through json without error and keeps the key set.
    parsed = json.loads(json.dumps(res))
    assert set(parsed.keys()) == {
        "target", "attack", "duration_sec", "workers", "ramp", "stats", "per_step", "breaking_rps"
    }
