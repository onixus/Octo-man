from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from .alive_filters import filter_alive_hosts
from .batch_runner import run_batches_parallel
from .batching import expand_batches, single_batch
from .checkpoint import CheckpointStore
from .config_schema import AppConfig, ProfileConfig
from .coverage_tracker import CoverageTracker, batches_are_disjoint
from .discover import host_discovery
from .protocol import parse_endpoint
from .utils import read_lines, write_lines


def _wave2_rate(profile: ProfileConfig, configured: int | None) -> int:
    if configured is not None:
        return configured
    return max(500, profile.discover_rate // 4)


def _discover_concurrency(
    config: AppConfig,
    batches: list[tuple[str, list[str]]],
    *,
    skip_known_alive: bool,
) -> int:
    """Return discover worker count: parallel when batches are disjoint, else serial if skipping known alive."""
    disjoint = config.discovery.disjoint_batches and batches_are_disjoint(batches)
    if disjoint:
        return config.runtime.discover_concurrency
    if skip_known_alive:
        return 1
    return config.runtime.discover_concurrency


def _make_batches(config: AppConfig, items: list[str]) -> list[tuple[str, list[str]]]:
    batching = config.batching
    if batching.enabled:
        return expand_batches(
            items,
            ipv4_prefix=batching.ipv4_prefix,
            max_targets_per_batch=batching.max_targets_per_batch,
        )
    return single_batch(items)


def _run_discover_batches(
    *,
    stage: str,
    checkpoint_key: str,
    batches: list[tuple[str, list[str]]],
    alive_set: set[str],
    alive_file: Path,
    output_dir: Path,
    rate: int,
    timeout: int,
    retries: int,
    skip_discovery: bool,
    skip_known_alive: bool,
    concurrency: int,
    checkpoint: CheckpointStore,
    done_ids: set[str],
) -> None:
    def _discover_batch(bid: str, members: list[str]) -> list[str]:
        known = set(alive_set) if skip_known_alive else None
        return host_discovery(
            members,
            output_dir=output_dir,
            rate=rate,
            timeout=timeout,
            retries=retries,
            skip_discovery=skip_discovery,
            known_alive=known,
            skip_known_alive=skip_known_alive,
            max_pending_hosts=65536,
            tag=bid,
        )

    run_batches_parallel(
        stage=stage,
        batches=batches,
        done_ids=done_ids,
        concurrency=concurrency,
        process_batch=_discover_batch,
        aggregate=alive_set,
        aggregate_file=alive_file,
        checkpoint=checkpoint,
        checkpoint_key=checkpoint_key,
    )


def _apply_alive_filters(hosts: set[str], config: AppConfig, alive_file: Path) -> set[str]:
    filtered = set(
        filter_alive_hosts(
            sorted(hosts),
            exclude_hosts=config.discovery.exclude_alive,
            exclude_last_octets=config.discovery.exclude_last_octets,
        )
    )
    write_lines(alive_file, sorted(filtered))
    return filtered


def run_discovery_stage(
    *,
    all_targets: list[str],
    config: AppConfig,
    profile: ProfileConfig,
    output_dir: Path,
    alive_file: Path,
    timeout: int,
    retries: int,
    checkpoint: CheckpointStore,
    resume: bool,
    make_batches: Callable[[list[str]], list[tuple[str, list[str]]]] | None = None,
) -> list[str]:
    """Run wave-1 (batched) and optional adaptive wave-2 host discovery."""
    if resume and checkpoint.is_done("discover"):
        return sorted(set(read_lines(alive_file)))

    batch_fn = make_batches or (lambda items: _make_batches(config, items))
    alive_set: set[str] = set(read_lines(alive_file)) if resume and alive_file.exists() else set()
    discovery = config.discovery
    runtime = config.runtime

    wave1_done = checkpoint.done_items("discover") if resume else set()
    wave1_batches = batch_fn(all_targets)
    disjoint = discovery.disjoint_batches and batches_are_disjoint(wave1_batches)
    skip_known = discovery.skip_known_alive and not disjoint
    wave1_workers = _discover_concurrency(config, wave1_batches, skip_known_alive=skip_known)
    if skip_known and runtime.discover_concurrency > 1:
        logging.info(
            "discovery: overlapping batches — sequential discover with skip_known_alive",
        )
    elif disjoint:
        logging.info(
            "discovery: disjoint batches — parallel discover (concurrency=%s)",
            wave1_workers,
        )

    _run_discover_batches(
        stage="discover",
        checkpoint_key="discover",
        batches=wave1_batches,
        alive_set=alive_set,
        alive_file=alive_file,
        output_dir=output_dir,
        rate=profile.discover_rate,
        timeout=timeout,
        retries=retries,
        skip_discovery=discovery.skip_discovery,
        skip_known_alive=skip_known,
        concurrency=wave1_workers,
        checkpoint=checkpoint,
        done_ids=wave1_done,
    )
    alive_set = _apply_alive_filters(alive_set, config, alive_file)

    adaptive = discovery.adaptive
    if adaptive.enabled and not discovery.skip_discovery:
        tracker = CoverageTracker.from_targets(
            all_targets,
            max_scope_hosts=adaptive.max_gap_hosts,
        )
        tracker.mark_found(alive_set)
        gap = tracker.gap()
        stats = tracker.stats()
        logging.info(
            "discovery adaptive: scope=%s found=%s gap=%s (%.1f%%)",
            stats["scope_hosts"],
            stats["found_hosts"],
            stats["gap_hosts"],
            stats["coverage_pct"],
        )
        if len(gap) >= adaptive.min_gap:
            wave2_rate = _wave2_rate(profile, adaptive.wave2_rate)
            logging.info(
                "discovery wave2: %s gap host(s) at rate %s",
                len(gap),
                wave2_rate,
            )
            wave2_batches = batch_fn(gap)
            wave2_disjoint = discovery.disjoint_batches and batches_are_disjoint(wave2_batches)
            wave2_workers = _discover_concurrency(
                config,
                wave2_batches,
                skip_known_alive=True,
            )
            if wave2_disjoint and wave2_workers > 1:
                logging.info(
                    "discovery wave2: disjoint batches — parallel discover (concurrency=%s)",
                    wave2_workers,
                )
            wave2_done = checkpoint.done_items("discover-wave2") if resume else set()
            _run_discover_batches(
                stage="discover-wave2",
                checkpoint_key="discover-wave2",
                batches=wave2_batches,
                alive_set=alive_set,
                alive_file=alive_file,
                output_dir=output_dir,
                rate=wave2_rate,
                timeout=timeout,
                retries=retries,
                skip_discovery=False,
                skip_known_alive=True,
                concurrency=wave2_workers,
                checkpoint=checkpoint,
                done_ids=wave2_done,
            )
            alive_set = _apply_alive_filters(alive_set, config, alive_file)
        checkpoint.mark_done("discover-wave2")

    checkpoint.mark_done("discover")
    return sorted(alive_set)


def verify_alive_without_ports(
    *,
    alive_hosts: list[str],
    open_ports: list[str],
    config: AppConfig,
    profile: ProfileConfig,
    output_dir: Path,
    timeout: int,
    retries: int,
) -> list[str]:
    """Re-probe alive hosts with no open ports at a lower rate; drop unconfirmed."""
    verify = config.discovery.verify
    if not verify.enabled or config.discovery.skip_discovery:
        return alive_hosts

    hosts_with_ports: set[str] = set()
    for entry in open_ports:
        parsed = parse_endpoint(entry)
        if parsed is not None:
            hosts_with_ports.add(parsed.host)

    suspects = sorted({host for host in alive_hosts if host not in hosts_with_ports})
    if not suspects:
        return alive_hosts

    rate = verify.rate if verify.rate is not None else max(500, profile.discover_rate // 4)
    logging.info(
        "discovery verify: re-probing %s alive host(s) without open ports at rate %s",
        len(suspects),
        rate,
    )
    confirmed = host_discovery(
        suspects,
        output_dir=output_dir,
        rate=rate,
        timeout=timeout,
        retries=retries,
        skip_discovery=False,
        tag="verify",
    )
    confirmed_set = set(confirmed)
    kept = sorted({host for host in alive_hosts if host in hosts_with_ports or host in confirmed_set})
    dropped = len(alive_hosts) - len(kept)
    if dropped:
        logging.info("discovery verify: dropped %s unconfirmed alive host(s)", dropped)
    return kept
