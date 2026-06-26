from __future__ import annotations

from pathlib import Path

from .utils import run_command, write_lines


def host_discovery(
    targets: list[str],
    output_dir: Path,
    rate: int,
    timeout: int,
    retries: int,
    skip_discovery: bool,
    tag: str = "all",
) -> list[str]:
    """Run naabu host discovery for a single batch of targets.

    Per-batch inputs/outputs live under ``output_dir/discover/<tag>.*`` so each
    batch is independent and resumable. Returns the alive hosts for this batch.
    """
    batch_dir = output_dir / "discover"
    input_file = batch_dir / f"{tag}.targets.txt"
    alive_file = batch_dir / f"{tag}.alive.txt"
    write_lines(input_file, targets)
    if not targets:
        write_lines(alive_file, [])
        return []

    if skip_discovery:
        alive = sorted(set(targets))
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
            "1",
        ],
        timeout=timeout,
        retries=retries,
    )
    alive = sorted({line.strip() for line in (result.stdout or "").splitlines() if line.strip()})
    write_lines(alive_file, alive)
    return alive
