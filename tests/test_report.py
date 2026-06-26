from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.report import _parse_nmap_xml, build_reports

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <os>
      <osmatch name="Linux 5.x" accuracy="95"/>
      <osmatch name="Linux 4.x" accuracy="88"/>
    </os>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.25"/>
        <script id="http-server-header" output="nginx/1.25"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
        <script id="smb-vuln-ms17-010" output="State: VULNERABLE"/>
      </port>
      <port protocol="tcp" portid="9">
        <state state="closed"/>
        <service name="discard"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _setup(tmp_path: Path) -> Path:
    nmap_dir = tmp_path / "nmap"
    nmap_dir.mkdir()
    (nmap_dir / "10.0.0.5.xml").write_text(SAMPLE_XML, encoding="utf-8")
    return nmap_dir


def test_parse_nmap_xml_extracts_services_os_and_scripts(tmp_path: Path):
    nmap_dir = _setup(tmp_path)
    services, os_matches, scripts = _parse_nmap_xml(nmap_dir)

    assert {s["port"] for s in services} == {"80", "445"}  # closed port excluded
    assert len(os_matches) == 2
    vuln = [s for s in scripts if s["vulnerable"]]
    assert len(vuln) == 1
    assert vuln[0]["script_id"] == "smb-vuln-ms17-010"


def test_build_reports_writes_os_and_vuln_artifacts(tmp_path: Path):
    nmap_dir = _setup(tmp_path)
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    build_reports(
        output_dir=output_dir,
        total_targets=10,
        alive_hosts=["10.0.0.5"],
        open_ports=["10.0.0.5:80", "10.0.0.5:445"],
        nmap_dir=nmap_dir,
        markdown_summary=True,
        html_summary=True,
        csv_export=True,
        json_export=True,
    )

    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["os_detected_hosts"] == 1
    assert summary["potential_vulnerabilities"] == 1

    vulns = json.loads((output_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert vulns[0]["script_id"] == "smb-vuln-ms17-010"

    os_findings = json.loads((output_dir / "os_findings.json").read_text(encoding="utf-8"))
    assert any(m["name"] == "Linux 5.x" for m in os_findings)

    md = (output_dir / "summary.md").read_text(encoding="utf-8")
    assert "Operating Systems" in md
    assert "Linux 5.x" in md
