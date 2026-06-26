from __future__ import annotations

from pathlib import Path

from scanner.pipeline.nse import (
    _build_nmap_command,
    _group_ports_by_host,
    _parse_host_port,
    _per_process_rate,
    _safe_filename,
)


def test_group_ports_by_host_groups_and_sorts():
    entries = ["10.0.0.1:443", "10.0.0.1:80", "10.0.0.2:22"]
    grouped = _group_ports_by_host(entries)
    assert grouped == {"10.0.0.1": ["80", "443"], "10.0.0.2": ["22"]}


def test_group_ports_by_host_dedupes_ports():
    grouped = _group_ports_by_host(["10.0.0.1:80", "10.0.0.1:80"])
    assert grouped == {"10.0.0.1": ["80"]}


def test_group_ports_by_host_ignores_malformed_entries():
    grouped = _group_ports_by_host(["bad-entry", "10.0.0.1:notaport", "10.0.0.2:8080"])
    assert grouped == {"10.0.0.2": ["8080"]}


def test_parse_host_port_ipv4():
    assert _parse_host_port("10.0.0.1:443") == ("10.0.0.1", "443")


def test_parse_host_port_bracketed_ipv6():
    assert _parse_host_port("[2001:db8::1]:443") == ("2001:db8::1", "443")


def test_parse_host_port_rejects_invalid():
    assert _parse_host_port("no-port") is None
    assert _parse_host_port("[2001:db8::1]:notaport") is None
    assert _parse_host_port("") is None


def test_group_ports_by_host_handles_ipv6():
    grouped = _group_ports_by_host(["[2001:db8::1]:80", "[2001:db8::1]:443"])
    assert grouped == {"2001:db8::1": ["80", "443"]}


def test_safe_filename_replaces_separators():
    assert _safe_filename("2001:db8::1") == "2001_db8__1"


def test_per_process_rate_splits_budget():
    assert _per_process_rate(2000, 4) == 500
    assert _per_process_rate(0, 4) == 0  # unlimited
    assert _per_process_rate(3, 8) == 1  # never drops below 1 when budget set
    assert _per_process_rate(1000, 0) == 1000  # guards against zero workers


def test_build_nmap_command_includes_os_and_rate():
    cmd = _build_nmap_command(
        "10.0.0.1",
        ["80", "443"],
        Path("/tmp/out/10.0.0.1"),
        scripts="default,safe,vuln",
        version_detection=True,
        os_detection=True,
        nmap_timing="T4",
        per_process_rate=500,
    )
    assert "-sV" in cmd
    assert "-O" in cmd and "--osscan-guess" in cmd
    assert cmd[cmd.index("--max-rate") + 1] == "500"
    assert cmd[cmd.index("-p") + 1] == "80,443"
    assert cmd[-1] == "10.0.0.1"


def test_build_nmap_command_omits_rate_when_unlimited():
    cmd = _build_nmap_command(
        "10.0.0.1",
        ["80"],
        Path("/tmp/out/10.0.0.1"),
        scripts="default,safe",
        version_detection=False,
        os_detection=False,
        nmap_timing="T3",
        per_process_rate=0,
    )
    assert "--max-rate" not in cmd
    assert "-sV" not in cmd
    assert "-O" not in cmd
