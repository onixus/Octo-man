from __future__ import annotations

import logging
from pathlib import Path

from .discovery_targets import filter_hosts_in_scope, pending_discovery_targets
from .utils import run_command, write_lines


def host_discovery(
    targets: list[str],
    output_dir: Path,
    rate: int,
    timeout: int,
    retries: int,
    skip_discovery: bool,
    known_alive: set[str] | None = None,
    skip_known_alive: bool = False,
    max_pending_hosts: int | None = 65536,
    tag: str = "all",
) -> list[str]:
    """Run naabu host discovery for a single batch of targets.

    Per-batch inputs/outputs live under ``output_dir/discover/<tag>.*`` so each
    batch is independent and resumable. Returns the alive hosts for this batch.
    """
    batch_dir = output_dir / "discover"
    input_file = batch_dir / f"{tag}.targets.txt"
    alive_file = batch_dir / f"{tag}.alive.txt"
    scan_targets = list(targets)
    if skip_known_alive and known_alive is not None:
        scan_targets = pending_discovery_targets(
            targets,
            known_alive,
            max_hosts=max_pending_hosts,
        )
        if not scan_targets:
            logging.info(
                "Discovery batch %s: skipping — all targets already alive (%s known)",
                tag,
                len(known_alive),
            )
            write_lines(input_file, [])
            write_lines(alive_file, [])
            return []

    write_lines(input_file, scan_targets)
    if not scan_targets:
        write_lines(alive_file, [])
        return []

    if skip_discovery:
        alive = sorted(set(scan_targets))
        write_lines(alive_file, alive)
        return alive

    # naabu prints alive hosts to stdout in -sn mode (the -o file stays empty),
    # so parse stdout and persist it to the per-batch file for artifacts.
    result = run_command(
        [
            "naabu",
            "-list",
            str(input_file),
            "-sn",
            "-silent",
            "-rate",
            str(rate),
            "-retries",
            str(max(1, retries)),
        ],
        timeout=timeout,
        retries=retries,
    )
    alive = sorted({line.strip() for line in (result.stdout or "").splitlines() if line.strip()})
    alive = filter_hosts_in_scope(alive, targets)
    write_lines(alive_file, alive)
    return alive
