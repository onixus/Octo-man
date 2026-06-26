from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from pydantic import ValidationError

from scanner import exit_codes
from scanner.pipeline.batching import expand_batches, single_batch
from scanner.pipeline.batch_runner import run_batches_parallel
from scanner.pipeline.checkpoint import CheckpointStore
from scanner.pipeline.config_schema import AppConfig, format_validation_error, load_config
from scanner.pipeline.contract import validate_inputs
from scanner.pipeline.discover import host_discovery
from scanner.pipeline.errors import StageFailureError
from scanner.pipeline.nse import run_nse
from scanner.pipeline.ports import fast_port_scan
from scanner.pipeline.report import build_reports
from scanner.pipeline.resolve import resolve_fqdns
from scanner.pipeline.run_context import resolve_run_paths, write_run_meta
from scanner.pipeline.utils import load_yaml, read_lines, setup_logging, write_lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Containerized network scan pipeline")
    parser.add_argument("--config", default="scanner/config/default.yaml", help="Path to YAML config")
    parser.add_argument("--ranges", default="scanner/inputs/ranges.txt", help="Path to CIDR/IP inputs")
    parser.add_argument("--domains", default="scanner/inputs/domains.txt", help="Path to FQDN inputs")
    parser.add_argument("--mode", choices=["safe", "balanced", "fast"], help="Override speed profile")
    parser.add_argument("--run-id", help="Run identifier for per-run output dirs (required for explicit resume)")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    return parser.parse_args()


def _run_stage(stage: str, func):  # type: ignore[no-untyped-def]
    try:
        return func()
    except Exception as exc:  # noqa: BLE001
        raise StageFailureError(stage, exc) from exc


def _run_pipeline(args: argparse.Namespace) -> int:
    raw = load_yaml(Path(args.config))
    try:
        config: AppConfig = load_config(raw)
    except ValidationError as exc:
        print(format_validation_error(exc), file=sys.stderr)
        return exit_codes.CONFIG_ERROR

    profile_name = args.mode or config.runtime.mode
    profile = config.profiles[profile_name]

    try:
        paths = resolve_run_paths(config.runtime, run_id=args.run_id, resume=args.resume)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return exit_codes.CONFIG_ERROR

    paths.output_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.logs_dir.mkdir(parents=True, exist_ok=True)

    setup_logging(
        paths.logs_dir / "pipeline.log",
        max_bytes=config.runtime.log_max_bytes,
        backup_count=config.runtime.log_backup_count,
    )
    logging.info("Starting scan pipeline in '%s' mode (run_id=%s, ports=%s)", profile_name, paths.run_id, config.ports.protocol)
    if not args.resume:
        write_run_meta(paths, profile_name, args.config)

    runtime = config.runtime
    retries = runtime.retries
    timeout = runtime.timeout_seconds
    checkpoint = CheckpointStore(paths.state_dir / "checkpoint.json")

    if not args.resume:
        checkpoint.clear()

    contract = validate_inputs(Path(args.ranges), Path(args.domains), paths.output_dir)
    checkpoint.mark_done("contract")
    if not contract.valid_ips_or_cidr and not contract.valid_fqdns:
        logging.error("No valid targets after input validation")
        return exit_codes.INPUT_ERROR

    if args.resume and checkpoint.is_done("resolve"):
        resolved_ips = read_lines(paths.output_dir / "resolved_ips.txt")
    else:
        resolved_ips = _run_stage(
            "resolve",
            lambda: resolve_fqdns(contract.valid_fqdns, paths.output_dir, timeout=timeout, retries=retries),
        )
        checkpoint.mark_done("resolve")

    all_targets = sorted(set(contract.valid_ips_or_cidr + resolved_ips))
    write_lines(paths.output_dir / "all_targets.txt", all_targets)

    batching = config.batching

    def make_batches(items: list[str]) -> list[tuple[str, list[str]]]:
        if batching.enabled:
            return expand_batches(
                items,
                ipv4_prefix=batching.ipv4_prefix,
                max_targets_per_batch=batching.max_targets_per_batch,
            )
        return single_batch(items)

    alive_file = paths.output_dir / "alive_ips.txt"
    if args.resume and checkpoint.is_done("discover"):
        alive_hosts = sorted(set(read_lines(alive_file)))
    else:
        alive_set: set[str] = set(read_lines(alive_file)) if args.resume else set()
        batches = make_batches(all_targets)
        run_batches_parallel(
            stage="discover",
            batches=batches,
            done_ids=checkpoint.done_items("discover"),
            concurrency=runtime.discover_concurrency,
            process_batch=lambda bid, members: host_discovery(
                members,
                output_dir=paths.output_dir,
                rate=profile.discover_rate,
                timeout=timeout,
                retries=retries,
                skip_discovery=config.discovery.skip_discovery,
                tag=bid,
            ),
            aggregate=alive_set,
            aggregate_file=alive_file,
            checkpoint=checkpoint,
            checkpoint_key="discover",
        )
        checkpoint.mark_done("discover")
        alive_hosts = sorted(alive_set)

    open_file = paths.output_dir / "open_ports.txt"
    if args.resume and checkpoint.is_done("ports"):
        open_ports = sorted(set(read_lines(open_file)))
    else:
        open_set: set[str] = set(read_lines(open_file)) if args.resume else set()
        custom_ports_file = Path(config.ports.custom_ports_file)
        custom_udp_ports_file = Path(config.ports.custom_udp_ports_file)
        port_cfg = config.ports
        batches = make_batches(alive_hosts)
        run_batches_parallel(
            stage="ports",
            batches=batches,
            done_ids=checkpoint.done_items("ports"),
            concurrency=runtime.ports_concurrency,
            process_batch=lambda bid, members: fast_port_scan(
                members,
                output_dir=paths.output_dir,
                rate=profile.port_rate,
                top_ports=profile.top_ports,
                top_udp_ports=port_cfg.top_udp_ports,
                timeout=timeout,
                retries=retries,
                protocol_mode=port_cfg.protocol,
                custom_ports_file=custom_ports_file,
                custom_udp_ports_file=custom_udp_ports_file,
                udp_probes=port_cfg.udp_probes,
                tag=bid,
            ),
            aggregate=open_set,
            aggregate_file=open_file,
            checkpoint=checkpoint,
            checkpoint_key="ports",
        )
        checkpoint.mark_done("ports")
        open_ports = sorted(open_set)

    if args.resume and checkpoint.is_done("nse"):
        nmap_dir = paths.output_dir / "nmap"
    else:
        nse_profile = config.nse_profiles[profile.nse_profile]
        nse_timeout = runtime.nse_timeout_seconds
        nse_concurrency = profile.nse_concurrency or runtime.nse_concurrency
        nse_max_rate = profile.nse_max_rate if profile.nse_max_rate is not None else runtime.nse_max_rate
        nmap_dir = _run_stage(
            "nse",
            lambda: run_nse(
                open_ports,
                output_dir=paths.output_dir,
                scripts=nse_profile.scripts,
                version_detection=nse_profile.version_detection,
                os_detection=nse_profile.os_detection,
                nmap_timing=profile.nmap_timing,
                timeout=nse_timeout,
                retries=retries,
                concurrency=nse_concurrency,
                max_rate=nse_max_rate,
                hosts_per_scan=runtime.nse_hosts_per_scan,
                done_hosts=checkpoint.done_items("nse") if args.resume else set(),
                on_host_done=lambda host: checkpoint.mark_item_done("nse", host),
            ),
        )
        checkpoint.mark_done("nse")

    reporting = config.reporting
    build_reports(
        output_dir=paths.output_dir,
        total_targets=len(all_targets),
        alive_hosts=alive_hosts,
        open_ports=open_ports,
        nmap_dir=nmap_dir,
        markdown_summary=reporting.markdown_summary,
        html_summary=reporting.html_summary,
        csv_export=reporting.csv_export,
        json_export=reporting.json_export,
    )
    checkpoint.mark_done("report")

    logging.info("Pipeline finished. Output directory: %s", paths.output_dir)
    return exit_codes.SUCCESS


def main() -> int:
    args = parse_args()
    try:
        return _run_pipeline(args)
    except StageFailureError as exc:
        logging.error("%s", exc)
        return exit_codes.STAGE_FAILURE
    except KeyboardInterrupt:
        logging.warning("Pipeline interrupted")
        return exit_codes.INTERRUPTED
    except Exception:
        logging.exception("Unexpected pipeline failure")
        return exit_codes.GENERAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
