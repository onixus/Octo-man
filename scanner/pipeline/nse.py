from __future__ import annotations

import hashlib
import ipaddress
import logging
from collections import defaultdict
from collections.abc import Callable, Iterable
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


def _format_nmap_host(host: str) -> str:
    """Format a host for nmap CLI (bracket IPv6 literals)."""
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]"
    except ValueError:
        pass
    return host


def _per_process_rate(max_rate: int, workers: int) -> int:
    """Split a global packets/sec budget across concurrent nmap processes."""
    if max_rate <= 0:
        return 0
    return max(1, max_rate // max(1, workers))


def _group_output_basename(hosts: list[str]) -> str:
    if len(hosts) == 1:
        return _safe_filename(hosts[0])
    digest = hashlib.sha1(",".join(sorted(hosts)).encode("utf-8")).hexdigest()[:12]
    return f"group_{digest}"


def _chunk_host_ports(host_ports: dict[str, list[str]], hosts_per_scan: int) -> list[dict[str, list[str]]]:
    """Split host->ports map into scan groups of up to ``hosts_per_scan`` hosts."""
    size = max(1, hosts_per_scan)
    items = sorted(host_ports.items())
    if size == 1:
        return [{host: ports} for host, ports in items]
    return [dict(items[i : i + size]) for i in range(0, len(items), size)]


def _build_nmap_command(
    host_ports: dict[str, list[str]],
    base: Path,
    scripts: str,
    version_detection: bool,
    os_detection: bool,
    nmap_timing: str,
    per_process_rate: int,
) -> list[str]:
    command = ["nmap", "-n", f"-{nmap_timing}"]
    if version_detection:
        command.append("-sV")
    if os_detection:
        command += ["-O", "--osscan-guess"]
    if per_process_rate > 0:
        command += ["--max-rate", str(per_process_rate)]
    command += ["--script", scripts]
    for host, ports in sorted(host_ports.items()):
        command += ["-p", ",".join(ports), _format_nmap_host(host)]
    command += ["-oA", str(base)]
    return command


def _group_ports_by_host(host_port_list: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for entry in host_port_list:
        parsed = _parse_host_port(entry)
        if parsed is None:
            continue
        host, port = parsed
        grouped[host].append(port)
    return {host: sorted(set(ports), key=int) for host, ports in grouped.items()}


def _scan_host_group(
    host_ports: dict[str, list[str]],
    nmap_output_dir: Path,
    scripts: str,
    version_detection: bool,
    os_detection: bool,
    nmap_timing: str,
    per_process_rate: int,
    timeout: int,
    retries: int,
) -> list[str]:
    hosts = sorted(host_ports)
    base = nmap_output_dir / _group_output_basename(hosts)
    command = _build_nmap_command(
        host_ports,
        base,
        scripts,
        version_detection,
        os_detection,
        nmap_timing,
        per_process_rate,
    )
    run_command(command, timeout=timeout, retries=retries, check=False, capture_output=False)
    return hosts


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
    max_rate: int = 0,
    hosts_per_scan: int = 1,
    done_hosts: Iterable[str] | None = None,
    on_host_done: Callable[[str], None] | None = None,
) -> Path:
    grouped = _group_ports_by_host(host_port_list)
    targets_file = output_dir / "nse_targets.txt"
    lines = [f"{host} {','.join(ports)}" for host, ports in grouped.items()]
    write_lines(targets_file, lines)

    nmap_output_dir = output_dir / "nmap"
    nmap_output_dir.mkdir(parents=True, exist_ok=True)
    if not grouped:
        return nmap_output_dir

    already_done = set(done_hosts or ())
    pending = {host: ports for host, ports in grouped.items() if host not in already_done}
    skipped = len(grouped) - len(pending)
    if skipped:
        logging.info("Resuming NSE: skipping %s already-scanned hosts", skipped)
    if not pending:
        return nmap_output_dir

    scan_groups = _chunk_host_ports(pending, hosts_per_scan)
    workers = max(1, concurrency)
    per_process_rate = _per_process_rate(max_rate, workers)
    logging.info(
        "Running NSE/OS scans for %s hosts in %s group(s) "
        "(hosts_per_scan=%s, concurrency=%s, global_max_rate=%s pps, per_process_rate=%s pps)",
        len(pending),
        len(scan_groups),
        max(1, hosts_per_scan),
        workers,
        max_rate if max_rate > 0 else "unlimited",
        per_process_rate if per_process_rate > 0 else "unlimited",
    )
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                _scan_host_group,
                group,
                nmap_output_dir,
                scripts,
                version_detection,
                os_detection,
                nmap_timing,
                per_process_rate,
                timeout,
                retries,
            ): group
            for group in scan_groups
        }
        for future in as_completed(futures):
            group = futures[future]
            try:
                completed_hosts = future.result()
            except Exception as exc:  # noqa: BLE001
                label = ",".join(sorted(group))
                logging.warning("NSE scan failed for group (%s hosts): %s", len(group), label[:120])
                logging.debug("NSE group failure detail: %s", exc)
                continue
            if on_host_done is not None:
                for host in completed_hosts:
                    on_host_done(host)

    return nmap_output_dir
