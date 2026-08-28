from __future__ import annotations

from click.testing import CliRunner

from ddos_tool.cli import main


def test_run_requires_target_and_attack_without_config() -> None:
    result = CliRunner().invoke(main, ["run"])
    assert result.exit_code != 0
    assert "provide --config" in result.output


def test_run_rejects_target_and_host_together() -> None:
    result = CliRunner().invoke(main, [
        "run", "--target", "127.0.0.1:9999", "--host", "127.0.0.1",
        "--port", "9999", "--attack", "udp",
    ])
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_run_rejects_attack_specific_option_mismatch() -> None:
    result = CliRunner().invoke(main, [
        "run", "--host", "127.0.0.1", "--port", "9999",
        "--attack", "tcp", "--udp-fill", "random",
    ])
    assert result.exit_code != 0
    assert "only valid with --attack udp" in result.output


def test_probe_rejects_invalid_port() -> None:
    result = CliRunner().invoke(main, ["probe", "127.0.0.1", "--ports", "0"])
    assert result.exit_code != 0
    assert "invalid port specification" in result.output


def test_run_rejects_replay_only_limit_for_other_attacks() -> None:
    result = CliRunner().invoke(main, [
        "run", "--host", "127.0.0.1", "--port", "9999",
        "--attack", "udp", "--max-packets", "10",
    ])
    assert result.exit_code != 0
    assert "only valid with --attack replay" in result.output


def test_find_limit_allows_max_rps_without_explicit_ramp(monkeypatch, tmp_path) -> None:
    config = tmp_path / "cfg.yaml"
    config.write_text("target: 127.0.0.1:9999\nattack: udp\nduration_sec: 1\n")

    class Bucket:
        rate = 1
        def set_rate(self, rate):
            self.rate = rate

    class FakeEngine:
        bucket = Bucket()
        stats = {"sent": 0, "err": 0, "ok": 0}
        breaking_rps = None
        async def run(self):
            await __import__("asyncio").sleep(0.01)
        def stop(self):
            pass

    monkeypatch.setattr("ddos_tool.cli._build_engine", lambda cfg: FakeEngine())
    result = CliRunner().invoke(main, ["run", "-c", str(config), "--find-limit", "--max-rps", "5000", "-d", "0.01", "-q"])
    assert result.exit_code == 0, result.output
    assert "UsageError" not in result.output
