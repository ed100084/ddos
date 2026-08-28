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
