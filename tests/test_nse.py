from __future__ import annotations

from scanner.pipeline.nse import _group_ports_by_host, _parse_host_port, _safe_filename


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
