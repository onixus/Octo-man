from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from .utils import save_json


def _host_address(host: ET.Element) -> str:
    for address in host.findall("address"):
        if address.attrib.get("addrtype") in ("ipv4", "ipv6"):
            return address.attrib.get("addr", "unknown")
    address_node = host.find("address")
    return address_node.attrib.get("addr", "unknown") if address_node is not None else "unknown"


def _parse_nmap_xml(nmap_dir: Path) -> tuple[list[dict], list[dict], list[dict]]:
    """Return (services, os_matches, script_findings) parsed from Nmap XML files."""
    services: list[dict] = []
    os_matches: list[dict] = []
    script_findings: list[dict] = []

    for xml_file in sorted(nmap_dir.glob("*.xml")):
        try:
            root = ET.fromstring(xml_file.read_text(encoding="utf-8"))
        except ET.ParseError:
            continue
        for host in root.findall("host"):
            address = _host_address(host)

            for osmatch in host.findall("./os/osmatch"):
                os_matches.append(
                    {
                        "host": address,
                        "name": osmatch.attrib.get("name", ""),
                        "accuracy": osmatch.attrib.get("accuracy", ""),
                    }
                )

            for script in host.findall("./hostscript/script"):
                script_findings.append(_script_record(address, "", script))

            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue
                service = port.find("service")
                portid = port.attrib.get("portid", "")
                services.append(
                    {
                        "host": address,
                        "port": portid,
                        "protocol": port.attrib.get("protocol", ""),
                        "service": (service.attrib.get("name", "unknown") if service is not None else "unknown"),
                        "product": (service.attrib.get("product", "") if service is not None else ""),
                        "version": (service.attrib.get("version", "") if service is not None else ""),
                    }
                )
                for script in port.findall("script"):
                    script_findings.append(_script_record(address, portid, script))

    return services, os_matches, script_findings


def _script_record(host: str, port: str, script: ET.Element) -> dict:
    output = (script.attrib.get("output", "") or "").strip()
    return {
        "host": host,
        "port": port,
        "script_id": script.attrib.get("id", ""),
        "output": output,
        "vulnerable": "VULNERABLE" in output.upper(),
    }


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
    findings, os_matches, script_findings = _parse_nmap_xml(nmap_dir)
    service_counter = Counter(item["service"] for item in findings)
    vulnerabilities = [item for item in script_findings if item["vulnerable"]]

    best_os_by_host: dict[str, dict] = {}
    for match in os_matches:
        host = match["host"]
        current = best_os_by_host.get(host)
        if current is None or int(match["accuracy"] or 0) > int(current["accuracy"] or 0):
            best_os_by_host[host] = match

    summary = {
        "total_targets": total_targets,
        "alive_hosts": len(alive_hosts),
        "open_host_port_pairs": len(open_ports),
        "nmap_open_services": len(findings),
        "os_detected_hosts": len(best_os_by_host),
        "nse_script_findings": len(script_findings),
        "potential_vulnerabilities": len(vulnerabilities),
        "top_services": service_counter.most_common(15),
    }
    save_json(output_dir / "summary.json", summary)

    # OS and NSE/vuln findings are core deliverables and always exported.
    save_json(output_dir / "os_findings.json", os_matches)
    save_json(output_dir / "script_findings.json", script_findings)
    save_json(output_dir / "vulnerabilities.json", vulnerabilities)

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
            f"- Hosts with OS detected: {summary['os_detected_hosts']}",
            f"- NSE script findings: {summary['nse_script_findings']}",
            f"- Potential vulnerabilities: {summary['potential_vulnerabilities']}",
            "",
            "## Top Services",
        ]
        for service, count in summary["top_services"]:
            md_lines.append(f"- {service}: {count}")

        md_lines += ["", "## Operating Systems"]
        if best_os_by_host:
            for host, match in sorted(best_os_by_host.items()):
                md_lines.append(f"- {host}: {match['name']} (accuracy {match['accuracy']}%)")
        else:
            md_lines.append("- none detected")

        md_lines += ["", "## Potential Vulnerabilities"]
        if vulnerabilities:
            for item in vulnerabilities:
                location = f"{item['host']}:{item['port']}" if item["port"] else item["host"]
                md_lines.append(f"- {location} [{item['script_id']}]")
        else:
            md_lines.append("- none detected")

        (output_dir / "summary.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    if html_summary:
        summary_md = (output_dir / "summary.md").read_text(encoding="utf-8") if (output_dir / "summary.md").exists() else ""
        html = (
            "<html><head><meta charset='utf-8'><title>Scan Summary</title></head><body><pre>"
            + summary_md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            + "</pre></body></html>"
        )
        (output_dir / "summary.html").write_text(html, encoding="utf-8")
