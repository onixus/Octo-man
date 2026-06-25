from __future__ import annotations

from pathlib import Path

from .utils import read_lines, run_command, write_lines


def _flatten_custom_ports(custom_file: Path) -> str | None:
    if not custom_file.exists():
        return None
    lines = read_lines(custom_file)
    if not lines:
        return None
    return ",".join(lines)


def fast_port_scan(
    alive_hosts: list[str],
    output_dir: Path,
    rate: int,
    top_ports: int,
    timeout: int,
    retries: int,
    custom_ports_file: Path,
) -> list[str]:
    input_file = output_dir / "alive_ips.txt"
    output_file = output_dir / "open_ports.txt"
    write_lines(input_file, alive_hosts)
    if not alive_hosts:
        write_lines(output_file, [])
        return []

    command = [
        "naabu",
        "-list",
        str(input_file),
        "-silent",
        "-rate",
        str(rate),
        "-retries",
        "1",
        "-o",
        str(output_file),
    ]
    custom_ports = _flatten_custom_ports(custom_ports_file)
    if custom_ports:
        command.extend(["-ports", custom_ports])
    else:
        command.extend(["-top-ports", str(top_ports)])

    run_command(command, timeout=timeout, retries=retries)
    entries = [line.strip() for line in output_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    write_lines(output_file, entries)
    return sorted(set(entries))
