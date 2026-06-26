from __future__ import annotations

import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .utils import run_command, write_lines


def _parse_host_port(entry: str) -> tuple[str, str] | None:
    """Split a naabu ``host:port`` entry, handling bracketed IPv6 (``[::1]:80``)."""
    entry = entry.strip()
    if not entry:
        return None
    if entry.startswith("[") and "]" in entry:
        host, _, rest = entry.partition("]")
        host = host[1:]
        port = rest.lstrip(":")
        if host and port.isdigit():
            return host, port
        return None
    host, sep, port = entry.rpartition(":")
    if not sep or not host or not port.isdigit():
        return None
    return host, port


def _safe_filename(host: str) -> str:
    return host.replace(":", "_").replace("/", "_")


def _group_ports_by_host(host_port_list: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for entry in host_port_list:
        parsed = _parse_host_port(entry)
        if parsed is None:
            continue
        host, port = parsed
        grouped[host].append(port)
    return {host: sorted(set(ports), key=int) for host, ports in grouped.items()}


def _scan_host(
    host: str,
    ports: list[str],
    nmap_output_dir: Path,
    scripts: str,
    version_detection: bool,
    os_detection: bool,
    nmap_timing: str,
    timeout: int,
    retries: int,
) -> None:
    base = nmap_output_dir / _safe_filename(host)
    command = ["nmap", "-n", f"-{nmap_timing}"]
    if version_detection:
        command.append("-sV")
    if os_detection:
        command += ["-O", "--osscan-guess"]
    command += ["--script", scripts, "-p", ",".join(ports), "-oA", str(base), host]
    run_command(command, timeout=timeout, retries=retries, check=False, capture_output=False)


def run_nse(
    host_port_list: list[str],
    output_dir: Path,
    scripts: str,
    version_detection: bool,
    os_detection: bool,
    nmap_timing: str,
    timeout: int,
    retries: int,
    concurrency: int,
) -> Path:
    grouped = _group_ports_by_host(host_port_list)
    targets_file = output_dir / "nse_targets.txt"
    lines = [f"{host} {','.join(ports)}" for host, ports in grouped.items()]
    write_lines(targets_file, lines)

    nmap_output_dir = output_dir / "nmap"
    nmap_output_dir.mkdir(parents=True, exist_ok=True)
    if not grouped:
        return nmap_output_dir

    workers = max(1, concurrency)
    logging.info("Running NSE/OS scans for %s hosts with concurrency %s", len(grouped), workers)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                _scan_host,
                host,
                ports,
                nmap_output_dir,
                scripts,
                version_detection,
                os_detection,
                nmap_timing,
                timeout,
                retries,
            ): host
            for host, ports in grouped.items()
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                future.result()
            except Exception as exc:  # noqa: BLE001
                logging.warning("NSE scan failed for %s: %s", host, exc)

    return nmap_output_dir
