#!/usr/bin/env python3
"""
Offensive Security Assessment Data Fusion Pipeline
Combines: Nmap XML (-oX) + Nessus XML (.nessus)
- Pseudonymizes all IP addresses and hostnames locally.
- Correlates open ports with confirmed vulnerabilities per asset.
- Inverts and clusters findings into High-Exploit vectors vs. Systemic flaws.
- Outputs a token-efficient JSON summary for Claude and a local mapping key.
"""

import collections
import json
import os
import sys
import xml.etree.ElementTree as ET

class IntelFusionEngine:
    def __init__(self):
        self.ip_map = {}
        self.host_counter = 1
        self.hosts_data = collections.defaultdict(lambda: {
            "token": "",
            "os": "Unknown",
            "open_ports": [],
            "vulns": []
        })
        self.vuln_clusters = {}

    def get_token(self, ip_or_name):
        if not ip_or_name:
            return ""
        if ip_or_name not in self.ip_map:
            token = f"TARGET_HOST_{self.host_counter:04d}"
            self.ip_map[ip_or_name] = token
            self.host_counter += 1
        return self.ip_map[ip_or_name]

    def parse_nmap(self, nmap_xml_path):
        """Extracts confirmed reachable ports, service banners, and protocol info."""
        print(f"[*] Ingesting Nmap scan: {nmap_xml_path}...")
        tree = ET.parse(nmap_xml_path)
        root = tree.getroot()

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue

            real_ip = None
            for addr in host.findall("address"):
                if addr.get("addrtype") in ["ipv4", "ipv6"]:
                    real_ip = addr.get("addr")
                    break

            if not real_ip:
                continue

            token = self.get_token(real_ip)
            self.hosts_data[token]["token"] = token

            # Extract Ports & Banners
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    port_id = port.get("portid")
                    proto = port.get("protocol")
                    service = port.find("service")
                    
                    svc_name = service.get("name", "unknown") if service is not None else "unknown"
                    svc_prod = service.get("product", "") if service is not None else ""
                    svc_ver = service.get("version", "") if service is not None else ""
                    banner = f"{svc_prod} {svc_ver}".strip()

                    entry = f"{port_id}/{proto}:{svc_name}" + (f" ({banner})" if banner else "")
                    if entry not in self.hosts_data[token]["open_ports"]:
                        self.hosts_data[token]["open_ports"].append(entry)

    def parse_nessus(self, nessus_file_path, min_severity=2):
        """Extracts Medium (2), High (3), and Critical (4) vulnerabilities with exploit tags."""
        print(f"[*] Ingesting Nessus scan: {nessus_file_path}...")
        tree = ET.parse(nessus_file_path)
        root = tree.getroot()

        report = root.find("Report")
        if report is None:
            print("[!] Warning: No <Report> block found in Nessus file.")
            return

        for host in report.findall("ReportHost"):
            raw_name = host.get("name", "")
            token = self.get_token(raw_name)
            self.hosts_data[token]["token"] = token

            # OS detection tag
            host_props = host.find("HostProperties")
            if host_props is not None:
                for tag in host_props.findall("tag"):
                    if tag.get("name") == "operating-system" and tag.text:
                        self.hosts_data[token]["os"] = tag.text

            for item in host.findall("ReportItem"):
                severity = int(item.get("severity", "0"))
                if severity < min_severity:
                    continue  # Discard Informational (0) and Low (1) noise

                plugin_id = item.get("pluginID")
                plugin_name = item.get("pluginName", "Unknown Vuln")
                port = item.get("port", "0")
                proto = item.get("protocol", "tcp")
                svc = item.get("svc_name", "general")

                has_exploit = item.find("exploit_available") is not None and item.find("exploit_available").text == "true"
                msf_exploit = item.find("exploit_framework_metasploit") is not None and item.find("exploit_framework_metasploit").text == "true"
                cves = [c.text for c in item.findall("cve") if c.text]
                cvss3 = item.find("cvss3_base_score")
                cvss_score = cvss3.text if cvss3 is not None else item.findtext("cvss_base_score", "N/A")

                sev_label = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM"}.get(severity, "MEDIUM")

                vuln_summary = {
                    "plugin_id": plugin_id,
                    "title": plugin_name,
                    "severity": sev_label,
                    "cvss": cvss_score,
                    "cve": cves[0] if cves else "N/A",
                    "port": f"{port}/{proto}",
                    "has_exploit": has_exploit,
                    "metasploit": msf_exploit
                }
                self.hosts_data[token]["vulns"].append(vuln_summary)

                # Cluster vulnerabilities across the entire fleet
                if plugin_id not in self.vuln_clusters:
                    self.vuln_clusters[plugin_id] = {
                        "plugin_id": plugin_id,
                        "title": plugin_name,
                        "severity": sev_label,
                        "cvss": cvss_score,
                        "cves": cves[:3],
                        "has_exploit": has_exploit,
                        "metasploit": msf_exploit,
                        "service": f"{port}/{proto} ({svc})",
                        "affected_count": 0,
                        "affected_hosts": [],
                        "solution": (item.findtext("solution") or "").strip()
                    }

                if token not in self.vuln_clusters[plugin_id]["affected_hosts"]:
                    self.vuln_clusters[plugin_id]["affected_hosts"].append(token)
                    self.vuln_clusters[plugin_id]["affected_count"] += 1

    def build_fused_payload(self, output_dir="processed_scans", base_name="enterprise_assessment"):
        os.makedirs(output_dir, exist_ok=True)
        
        # 1. Identify High Exploit Potential Hosts (Confirmed open port + weaponized CVE)
        high_leverage_targets = []
        for token, data in self.hosts_data.items():
            weaponized_vulns = [v for v in data["vulns"] if v["has_exploit"] or v["severity"] == "CRITICAL"]
            if weaponized_vulns or any("8080" in p or "6379" in p or "27017" in p or "445" in p for p in data["open_ports"]):
                high_leverage_targets.append({
                    "token": token,
                    "os": data["os"],
                    "open_ports": data["open_ports"][:10],
                    "critical_or_exploitable_vulns": weaponized_vulns
                })

        # 2. Sort Fleet Vulnerability Clusters
        sorted_clusters = list(self.vuln_clusters.values())
        sorted_clusters.sort(key=lambda x: (x["has_exploit"], x["severity"] == "CRITICAL", x["affected_count"]), reverse=True)

        fused_report = {
            "metadata": {
                "total_correlated_assets": len(self.hosts_data),
                "total_vulnerability_clusters": len(sorted_clusters),
                "high_priority_targets_count": len(high_leverage_targets)
            },
            "top_priority_attack_targets": high_leverage_targets[:30],
            "actionable_vulnerability_clusters": [
                {
                    "plugin_id": c["plugin_id"],
                    "title": c["title"],
                    "severity": c["severity"],
                    "cvss": c["cvss"],
                    "cves": c["cves"],
                    "has_public_exploit": c["has_exploit"],
                    "metasploit_available": c["metasploit"],
                    "affected_count": c["affected_count"],
                    "sample_hosts": c["affected_hosts"][:6],
                    "remediation_summary": c["solution"][:200]
                }
                for c in sorted_clusters
            ]
        }

        # Write output files
        json_output = os.path.join(output_dir, f"{base_name}_fused_summary.json")
        key_output = os.path.join(output_dir, f"{base_name}_MAPPING_KEY.json")

        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(fused_report, f, indent=2)

        with open(key_output, "w", encoding="utf-8") as f:
            json.dump(self.ip_map, f, indent=2)

        print(f"\n[+] Fusion completed successfully!")
        print(f"[+] Clean summary generated: {json_output}")
        print(f"[+] Total Assets: {len(self.hosts_data)} | High-Priority Attack Vectors: {len(high_leverage_targets)}")
        print(f"[+] Secure local translation key: {key_output}")


# ================= Execution =================
def main():
    if len(sys.argv) < 3:
        print("Usage: python fusion_preprocessor.py <nmap_scan.xml> <nessus_scan.nessus> [output_base_name]")
        sys.exit(1)

    nmap_path = sys.argv[1]
    nessus_path = sys.argv[2]
    base_name = sys.argv[3] if len(sys.argv) > 3 else "enterprise_fusion"

    engine = IntelFusionEngine()
    engine.parse_nmap(nmap_path)
    engine.parse_nessus(nessus_path)
    engine.build_fused_payload(base_name=base_name)

if __name__ == "__main__":
    main()
