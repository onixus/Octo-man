from __future__ import annotations

from pathlib import Path

from scanner.pipeline.nse import (
    _build_nmap_command,
    _chunk_host_ports,
    _format_nmap_host,
    _group_output_basename,
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


def test_format_nmap_host_brackets_ipv6():
    assert _format_nmap_host("2001:db8::1") == "[2001:db8::1]"
    assert _format_nmap_host("10.0.0.1") == "10.0.0.1"


def test_per_process_rate_splits_budget():
    assert _per_process_rate(2000, 4) == 500
    assert _per_process_rate(0, 4) == 0  # unlimited
    assert _per_process_rate(3, 8) == 1  # never drops below 1 when budget set
    assert _per_process_rate(1000, 0) == 1000  # guards against zero workers


def test_build_nmap_command_single_host():
    cmd = _build_nmap_command(
        {"10.0.0.1": ["80", "443"]},
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
    assert cmd[-1] == "/tmp/out/10.0.0.1"
    assert "10.0.0.1" in cmd


def test_build_nmap_command_multi_host_different_ports():
    cmd = _build_nmap_command(
        {"10.0.0.1": ["80"], "10.0.0.2": ["22", "443"]},
        Path("/tmp/out/group_abc"),
        scripts="default,safe",
        version_detection=False,
        os_detection=False,
        nmap_timing="T3",
        per_process_rate=0,
    )
    assert ["-p", "80", "10.0.0.1"] in [cmd[i : i + 3] for i in range(len(cmd) - 2)]
    assert ["-p", "22,443", "10.0.0.2"] in [cmd[i : i + 3] for i in range(len(cmd) - 2)]
    assert cmd[-1] == "/tmp/out/group_abc"


def test_build_nmap_command_multi_host_ipv6():
    cmd = _build_nmap_command(
        {"2001:db8::1": ["80"]},
        Path("/tmp/out/group_v6"),
        scripts="default",
        version_detection=False,
        os_detection=False,
        nmap_timing="T4",
        per_process_rate=0,
    )
    assert "[2001:db8::1]" in cmd


def test_build_nmap_command_omits_rate_when_unlimited():
    cmd = _build_nmap_command(
        {"10.0.0.1": ["80"]},
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


def test_chunk_host_ports_groups_hosts():
    host_ports = {
        "10.0.0.1": ["80"],
        "10.0.0.2": ["22"],
        "10.0.0.3": ["443"],
        "10.0.0.4": ["8080"],
    }
    groups = _chunk_host_ports(host_ports, 2)
    assert len(groups) == 2
    assert sum(len(group) for group in groups) == 4


def test_chunk_host_ports_one_per_group_when_size_one():
    host_ports = {"10.0.0.1": ["80"], "10.0.0.2": ["22"]}
    groups = _chunk_host_ports(host_ports, 1)
    assert groups == [{"10.0.0.1": ["80"]}, {"10.0.0.2": ["22"]}]


def test_group_output_basename_single_vs_multi():
    assert _group_output_basename(["10.0.0.1"]) == "10.0.0.1"
    multi = _group_output_basename(["10.0.0.1", "10.0.0.2"])
    assert multi.startswith("group_")
    assert len(multi) == len("group_") + 12
