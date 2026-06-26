from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from .utils import save_json


def _collect_nmap_services(nmap_dir: Path) -> list[dict]:
    findings: list[dict] = []
    for xml_file in sorted(nmap_dir.glob("*.xml")):
        try:
            root = ET.fromstring(xml_file.read_text(encoding="utf-8"))
        except ET.ParseError:
            continue
        for host in root.findall("host"):
            address_node = host.find("address")
            address = address_node.attrib.get("addr", "unknown") if address_node is not None else "unknown"
            for port in host.findall("./ports/port"):
                state = port.find("state")
                service = port.find("service")
                if state is None or state.attrib.get("state") != "open":
                    continue
                findings.append(
                    {
                        "host": address,
                        "port": port.attrib.get("portid", ""),
                        "protocol": port.attrib.get("protocol", ""),
                        "service": (service.attrib.get("name", "unknown") if service is not None else "unknown"),
                        "product": (service.attrib.get("product", "") if service is not None else ""),
                        "version": (service.attrib.get("version", "") if service is not None else ""),
                    }
                )
    return findings


def build_reports(
    output_dir: Path,
    total_targets: int,
    alive_hosts: list[str],
    open_ports: list[str],
    nmap_dir: Path,
    markdown_summary: bool,
    html_summary: bool,
    csv_export: bool,
    json_export: bool,
) -> None:
    findings = _collect_nmap_services(nmap_dir)
    service_counter = Counter(item["service"] for item in findings)

    summary = {
        "total_targets": total_targets,
        "alive_hosts": len(alive_hosts),
        "open_host_port_pairs": len(open_ports),
        "nmap_open_services": len(findings),
        "top_services": service_counter.most_common(15),
    }
    save_json(output_dir / "summary.json", summary)

    if json_export:
        save_json(output_dir / "findings.json", findings)
        (output_dir / "findings.jsonl").write_text(
            "".join(json.dumps(item, ensure_ascii=True) + "\n" for item in findings),
            encoding="utf-8",
        )

    if csv_export:
        csv_path = output_dir / "findings.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["host", "port", "protocol", "service", "product", "version"])
            writer.writeheader()
            writer.writerows(findings)

    if markdown_summary:
        md_lines = [
            "# Scan Summary",
            "",
            f"- Total targets: {summary['total_targets']}",
            f"- Alive hosts: {summary['alive_hosts']}",
            f"- Open host:port pairs: {summary['open_host_port_pairs']}",
            f"- Parsed open services from Nmap XML: {summary['nmap_open_services']}",
            "",
            "## Top Services",
        ]
        for service, count in summary["top_services"]:
            md_lines.append(f"- {service}: {count}")
        (output_dir / "summary.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    if html_summary:
        summary_md = (output_dir / "summary.md").read_text(encoding="utf-8") if (output_dir / "summary.md").exists() else ""
        html = (
            "<html><head><meta charset='utf-8'><title>Scan Summary</title></head><body><pre>"
            + summary_md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            + "</pre></body></html>"
        )
        (output_dir / "summary.html").write_text(html, encoding="utf-8")
