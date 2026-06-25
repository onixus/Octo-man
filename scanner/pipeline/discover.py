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
) -> list[str]:
    input_file = output_dir / "all_targets.txt"
    alive_file = output_dir / "alive_ips.txt"
    write_lines(input_file, targets)
    if not targets:
        write_lines(alive_file, [])
        return []

    if skip_discovery:
        write_lines(alive_file, targets)
        return sorted(set(targets))

    run_command(
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
            "-o",
            str(alive_file),
        ],
        timeout=timeout,
        retries=retries,
    )
    alive = [line.strip() for line in alive_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    write_lines(alive_file, alive)
    return sorted(set(alive))
