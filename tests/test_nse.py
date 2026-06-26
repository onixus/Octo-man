from __future__ import annotations

from scanner.pipeline.nse import _group_ports_by_host


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
