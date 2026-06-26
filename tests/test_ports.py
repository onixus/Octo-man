from __future__ import annotations

from pathlib import Path

from scanner.pipeline.ports import _flatten_custom_ports


def test_flatten_custom_ports_missing_file(tmp_path: Path):
    assert _flatten_custom_ports(tmp_path / "nope.txt") is None


def test_flatten_custom_ports_only_comments(tmp_path: Path):
    f = tmp_path / "ports.txt"
    f.write_text("# use profile top-ports\n", encoding="utf-8")
    assert _flatten_custom_ports(f) is None


def test_flatten_custom_ports_joins_lines(tmp_path: Path):
    f = tmp_path / "ports.txt"
    f.write_text("22\n80,443\n1-1024\n", encoding="utf-8")
    assert _flatten_custom_ports(f) == "22,80,443,1-1024"
