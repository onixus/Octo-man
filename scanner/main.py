from __future__ import annotations

import argparse
import logging
from pathlib import Path

from scanner.pipeline.batching import expand_batches, single_batch
from scanner.pipeline.checkpoint import CheckpointStore
from scanner.pipeline.contract import validate_inputs
from scanner.pipeline.discover import host_discovery
from scanner.pipeline.nse import run_nse
from scanner.pipeline.ports import fast_port_scan
from scanner.pipeline.report import build_reports
from scanner.pipeline.resolve import resolve_fqdns
from scanner.pipeline.utils import load_yaml, read_lines, setup_logging, write_lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Containerized network scan pipeline")
    parser.add_argument("--config", default="scanner/config/default.yaml", help="Path to YAML config")
    parser.add_argument("--ranges", default="scanner/inputs/ranges.txt", help="Path to CIDR/IP inputs")
    parser.add_argument("--domains", default="scanner/inputs/domains.txt", help="Path to FQDN inputs")
    parser.add_argument("--mode", choices=["safe", "balanced", "fast"], help="Override speed profile")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_yaml(Path(args.config))

    runtime = config.get("runtime", {})
    profile_name = args.mode or runtime.get("mode", "balanced")
    profiles = config.get("profiles", {})
    profile = profiles.get(profile_name, profiles.get("balanced", {}))
    if not profile:
        raise ValueError(f"No profile found for mode '{profile_name}'")

    output_dir = Path(runtime.get("output_dir", "scanner/output"))
    state_dir = Path(runtime.get("state_dir", "scanner/state"))
    logs_dir = Path(runtime.get("logs_dir", "scanner/output/logs"))
    output_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    setup_logging(logs_dir / "pipeline.log")
    logging.info("Starting scan pipeline in '%s' mode", profile_name)

    retries = int(runtime.get("retries", 2))
    timeout = int(runtime.get("timeout_seconds", 1800))
    checkpoint = CheckpointStore(state_dir / "checkpoint.json")

    if not args.resume:
        checkpoint.clear()

    contract = validate_inputs(Path(args.ranges), Path(args.domains), output_dir)
    checkpoint.mark_done("contract")

    if args.resume and checkpoint.is_done("resolve"):
        resolved_ips = [line.strip() for line in (output_dir / "resolved_ips.txt").read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        resolved_ips = resolve_fqdns(contract.valid_fqdns, output_dir, timeout=timeout, retries=retries)
        checkpoint.mark_done("resolve")

    all_targets = sorted(set(contract.valid_ips_or_cidr + resolved_ips))
    write_lines(output_dir / "all_targets.txt", all_targets)

    batching_cfg = config.get("batching", {})
    batching_enabled = bool(batching_cfg.get("enabled", True))
    ipv4_prefix = int(batching_cfg.get("ipv4_prefix", 20))
    max_per_batch = int(batching_cfg.get("max_targets_per_batch", 4096))

    def make_batches(items: list[str]) -> list[tuple[str, list[str]]]:
        if batching_enabled:
            return expand_batches(items, ipv4_prefix=ipv4_prefix, max_targets_per_batch=max_per_batch)
        return single_batch(items)

    alive_file = output_dir / "alive_ips.txt"
    if args.resume and checkpoint.is_done("discover"):
        alive_hosts = sorted(set(read_lines(alive_file)))
    else:
        alive_set: set[str] = set(read_lines(alive_file)) if args.resume else set()
        done_discover = checkpoint.done_items("discover")
        skip_discovery = bool(config.get("discovery", {}).get("skip_discovery", False))
        discover_rate = int(profile.get("discover_rate", 3000))
        batches = make_batches(all_targets)
        logging.info("Discovery: %s batch(es)", len(batches))
        for index, (bid, members) in enumerate(batches, start=1):
            if bid in done_discover:
                continue
            logging.info("Discovery batch %s/%s (%s)", index, len(batches), bid)
            batch_alive = host_discovery(
                members,
                output_dir=output_dir,
                rate=discover_rate,
                timeout=timeout,
                retries=retries,
                skip_discovery=skip_discovery,
                tag=bid,
            )
            alive_set.update(batch_alive)
            write_lines(alive_file, sorted(alive_set))
            checkpoint.mark_item_done("discover", bid)
        checkpoint.mark_done("discover")
        alive_hosts = sorted(alive_set)

    open_file = output_dir / "open_ports.txt"
    if args.resume and checkpoint.is_done("ports"):
        open_ports = sorted(set(read_lines(open_file)))
    else:
        open_set: set[str] = set(read_lines(open_file)) if args.resume else set()
        done_ports = checkpoint.done_items("ports")
        port_rate = int(profile.get("port_rate", 3000))
        top_ports = int(profile.get("top_ports", 1000))
        custom_ports_file = Path(config.get("ports", {}).get("custom_ports_file", "scanner/inputs/ports.txt"))
        batches = make_batches(alive_hosts)
        logging.info("Port scan: %s batch(es)", len(batches))
        for index, (bid, members) in enumerate(batches, start=1):
            if bid in done_ports:
                continue
            logging.info("Port-scan batch %s/%s (%s)", index, len(batches), bid)
            batch_open = fast_port_scan(
                members,
                output_dir=output_dir,
                rate=port_rate,
                top_ports=top_ports,
                timeout=timeout,
                retries=retries,
                custom_ports_file=custom_ports_file,
                tag=bid,
            )
            open_set.update(batch_open)
            write_lines(open_file, sorted(open_set))
            checkpoint.mark_item_done("ports", bid)
        checkpoint.mark_done("ports")
        open_ports = sorted(open_set)

    if args.resume and checkpoint.is_done("nse"):
        nmap_dir = output_dir / "nmap"
    else:
        nse_profile_name = profile.get("nse_profile", "baseline")
        nse_profile = config.get("nse_profiles", {}).get(nse_profile_name, {})
        nse_timeout = int(runtime.get("nse_timeout_seconds", timeout))
        nse_concurrency = int(profile.get("nse_concurrency", runtime.get("nse_concurrency", 4)))
        nse_max_rate = int(profile.get("nse_max_rate", runtime.get("nse_max_rate", 0)))
        nmap_dir = run_nse(
            open_ports,
            output_dir=output_dir,
            scripts=str(nse_profile.get("scripts", "default,safe")),
            version_detection=bool(nse_profile.get("version_detection", True)),
            os_detection=bool(nse_profile.get("os_detection", False)),
            nmap_timing=str(profile.get("nmap_timing", "T4")),
            timeout=nse_timeout,
            retries=retries,
            concurrency=nse_concurrency,
            max_rate=nse_max_rate,
            done_hosts=checkpoint.done_items("nse") if args.resume else set(),
            on_host_done=lambda host: checkpoint.mark_item_done("nse", host),
        )
        checkpoint.mark_done("nse")

    build_reports(
        output_dir=output_dir,
        total_targets=len(all_targets),
        alive_hosts=alive_hosts,
        open_ports=open_ports,
        nmap_dir=nmap_dir,
        markdown_summary=bool(config.get("reporting", {}).get("markdown_summary", True)),
        html_summary=bool(config.get("reporting", {}).get("html_summary", True)),
        csv_export=bool(config.get("reporting", {}).get("csv_export", True)),
        json_export=bool(config.get("reporting", {}).get("json_export", True)),
    )
    checkpoint.mark_done("report")

    logging.info("Pipeline finished. Output directory: %s", output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
