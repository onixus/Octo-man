from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from .utils import run_command, write_lines


def _group_ports_by_host(host_port_list: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for entry in host_port_list:
        if ":" not in entry:
            continue
        host, port = entry.rsplit(":", 1)
        if port.isdigit():
            grouped[host].append(port)
    return {host: sorted(set(ports), key=int) for host, ports in grouped.items()}


def run_nse(
    host_port_list: list[str],
    output_dir: Path,
    scripts: str,
    version_detection: bool,
    nmap_timing: str,
    timeout: int,
    retries: int,
) -> Path:
    grouped = _group_ports_by_host(host_port_list)
    targets_file = output_dir / "nse_targets.txt"
    lines = [f"{host} {','.join(ports)}" for host, ports in grouped.items()]
    write_lines(targets_file, lines)

    nmap_output_dir = output_dir / "nmap"
    nmap_output_dir.mkdir(parents=True, exist_ok=True)
    if not grouped:
        return nmap_output_dir

    for host, ports in grouped.items():
        base = nmap_output_dir / host.replace(":", "_")
        command = ["nmap", "-n", f"-{nmap_timing}", "--script", scripts, "-p", ",".join(ports), "-oA", str(base), host]
        if version_detection:
            command.insert(1, "-sV")
        run_command(command, timeout=timeout, retries=retries, check=False)

    return nmap_output_dir
