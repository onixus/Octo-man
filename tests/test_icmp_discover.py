from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from scanner.pipeline.config_schema import IcmpDiscoveryConfig
from scanner.pipeline.discover import host_discovery
from scanner.pipeline.icmp_discover import icmp_ping_filter, parse_fping_output


def test_parse_fping_output_a_flag_ips():
    stdout = "10.0.0.1\n10.0.0.5\n"
    assert parse_fping_output(stdout) == ["10.0.0.1", "10.0.0.5"]


def test_parse_fping_output_is_alive_lines():
    stdout = "10.0.0.1 is alive\n10.0.0.2 is unreachable\n"
    assert parse_fping_output(stdout) == ["10.0.0.1"]


def test_icmp_ping_filter_splits_alive_and_pending(tmp_path: Path, monkeypatch):
    icmp = IcmpDiscoveryConfig(enabled=True, timeout_ms=300, retries=0)
    calls: list[list[str]] = []

    def fake_run_command(command, **kwargs):
        calls.append(command)
        result = MagicMock()
        result.stdout = "10.0.0.1\n10.0.0.3\n"
        return result

    monkeypatch.setattr("scanner.pipeline.icmp_discover.run_command", fake_run_command)
    alive, pending = icmp_ping_filter(
        ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        tmp_path,
        icmp,
        timeout=30,
        retries=1,
        tag="batch1",
    )
    assert alive == ["10.0.0.1", "10.0.0.3"]
    assert pending == ["10.0.0.2"]
    assert calls[0][:3] == ["fping", "-f", str(tmp_path / "discover" / "batch1.icmp.targets.txt")]
    assert (tmp_path / "discover" / "batch1.icmp.alive.txt").read_text(encoding="utf-8").splitlines() == [
        "10.0.0.1",
        "10.0.0.3",
    ]


def test_host_discovery_icmp_skips_naabu_when_all_respond(tmp_path: Path, monkeypatch):
    icmp = IcmpDiscoveryConfig(enabled=True)

    def fake_icmp(targets, output_dir, icmp_cfg, **kwargs):
        return sorted(targets), []

    naabu_called = {"value": False}

    def fake_run_command(command, **kwargs):
        naabu_called["value"] = True
        result = MagicMock()
        result.stdout = ""
        return result

    monkeypatch.setattr("scanner.pipeline.discover.icmp_ping_filter", fake_icmp)
    monkeypatch.setattr("scanner.pipeline.discover.run_command", fake_run_command)

    alive = host_discovery(
        ["10.0.0.1", "10.0.0.2"],
        tmp_path,
        rate=1000,
        timeout=30,
        retries=1,
        skip_discovery=False,
        icmp=icmp,
        tag="t1",
    )
    assert alive == ["10.0.0.1", "10.0.0.2"]
    assert naabu_called["value"] is False


def test_host_discovery_icmp_merges_naabu_results(tmp_path: Path, monkeypatch):
    icmp = IcmpDiscoveryConfig(enabled=True)

    def fake_icmp(targets, output_dir, icmp_cfg, **kwargs):
        return ["10.0.0.1"], ["10.0.0.2"]

    def fake_run_command(command, **kwargs):
        result = MagicMock()
        result.stdout = "10.0.0.2\n"
        return result

    monkeypatch.setattr("scanner.pipeline.discover.icmp_ping_filter", fake_icmp)
    monkeypatch.setattr("scanner.pipeline.discover.run_command", fake_run_command)

    alive = host_discovery(
        ["10.0.0.1", "10.0.0.2"],
        tmp_path,
        rate=1000,
        timeout=30,
        retries=1,
        skip_discovery=False,
        icmp=icmp,
        tag="t2",
    )
    assert alive == ["10.0.0.1", "10.0.0.2"]


def test_icmp_ping_filter_disabled_returns_empty_alive():
    icmp = IcmpDiscoveryConfig(enabled=False)
    alive, pending = icmp_ping_filter(
        ["10.0.0.1"],
        Path("/tmp/unused"),
        icmp,
        timeout=30,
        retries=1,
        tag="x",
    )
    assert alive == []
    assert pending == ["10.0.0.1"]
