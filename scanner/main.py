from __future__ import annotations

import argparse
import logging
from pathlib import Path

from scanner.pipeline.checkpoint import CheckpointStore
from scanner.pipeline.contract import validate_inputs
from scanner.pipeline.discover import host_discovery
from scanner.pipeline.nse import run_nse
from scanner.pipeline.ports import fast_port_scan
from scanner.pipeline.report import build_reports
from scanner.pipeline.resolve import resolve_fqdns
from scanner.pipeline.utils import load_yaml, setup_logging, write_lines


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

    if args.resume and checkpoint.is_done("discover"):
        alive_hosts = [line.strip() for line in (output_dir / "alive_ips.txt").read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        alive_hosts = host_discovery(
            all_targets,
            output_dir=output_dir,
            rate=int(profile.get("discover_rate", 3000)),
            timeout=timeout,
            retries=retries,
            skip_discovery=bool(config.get("discovery", {}).get("skip_discovery", False)),
        )
        checkpoint.mark_done("discover")

    if args.resume and checkpoint.is_done("ports"):
        open_ports = [line.strip() for line in (output_dir / "open_ports.txt").read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        open_ports = fast_port_scan(
            alive_hosts,
            output_dir=output_dir,
            rate=int(profile.get("port_rate", 3000)),
            top_ports=int(profile.get("top_ports", 1000)),
            timeout=timeout,
            retries=retries,
            custom_ports_file=Path(config.get("ports", {}).get("custom_ports_file", "scanner/inputs/ports.txt")),
        )
        checkpoint.mark_done("ports")

    if args.resume and checkpoint.is_done("nse"):
        nmap_dir = output_dir / "nmap"
    else:
        nse_profile_name = profile.get("nse_profile", "baseline")
        nse_profile = config.get("nse_profiles", {}).get(nse_profile_name, {})
        nse_timeout = int(runtime.get("nse_timeout_seconds", timeout))
        nse_concurrency = int(profile.get("nse_concurrency", runtime.get("nse_concurrency", 4)))
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
