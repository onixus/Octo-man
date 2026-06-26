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
    tag: str = "all",
) -> list[str]:
    """Run a naabu fast port scan for a single batch of alive hosts.

    Per-batch inputs/outputs live under ``output_dir/ports/<tag>.*``. Returns
    the ``host:port`` entries discovered for this batch.
    """
    batch_dir = output_dir / "ports"
    input_file = batch_dir / f"{tag}.hosts.txt"
    output_file = batch_dir / f"{tag}.open.txt"
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
    ]
    custom_ports = _flatten_custom_ports(custom_ports_file)
    if custom_ports:
        command.extend(["-ports", custom_ports])
    else:
        command.extend(["-top-ports", str(top_ports)])

    # Parse naabu stdout (host:port per line) and persist it for artifacts.
    result = run_command(command, timeout=timeout, retries=retries)
    entries = sorted({line.strip() for line in (result.stdout or "").splitlines() if line.strip()})
    write_lines(output_file, entries)
    return entries
