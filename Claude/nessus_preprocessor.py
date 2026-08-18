#!/usr/bin/env python3
"""
Nessus File Sanitizer & Risk-Aggregator
- Strips IPs, FQDNs, and MAC addresses.
- Filters out informational noise (Severity 0/1).
- Inverts findings into actionable vulnerability clusters with exploitability metadata.
- Outputs a compact JSON file ready for Claude triage.
"""

import collections
import json
import os
import sys
import xml.etree.ElementTree as ET

def parse_and_sanitize_nessus(nessus_file_path, output_dir="processed_scans", min_severity=2):
    """
    min_severity:
      0 = Info (Excluded)
      1 = Low (Excluded by default)
      2 = Medium
      3 = High
      4 = Critical
    """
    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(nessus_file_path))[0]

    tree = ET.parse(nessus_file_path)
    root = tree.getroot()

    ip_map = {}
    host_counter = 1

    # Map plugin_id -> aggregated vulnerability info
    vuln_clusters = {}
    host_summary = collections.defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "vulns": []})

    print(f"[*] Parsing and sanitizing {nessus_file_path}...")

    report = root.find("Report")
    if report is None:
        print("[!] No <Report> block found in Nessus XML.", file=sys.stderr)
        return

    for host in report.findall("ReportHost"):
        raw_name = host.get("name", "")
        
        # 1. Tokenize Host Identifier
        if raw_name not in ip_map:
            token = f"TARGET_HOST_{host_counter:04d}"
            ip_map[raw_name] = token
            host_counter += 1
        else:
            token = ip_map[raw_name]

        # Extract OS if available
        os_name = "Unknown OS"
        host_props = host.find("HostProperties")
        if host_props is not None:
            for tag in host_props.findall("tag"):
                if tag.get("name") == "operating-system":
                    os_name = tag.text or "Unknown OS"

        # 2. Iterate Findings (ReportItems)
        for item in host.findall("ReportItem"):
            severity = int(item.get("severity", "0"))
            if severity < min_severity:
                continue  # Drop Informational & Low noise

            plugin_id = item.get("pluginID")
            plugin_name = item.get("pluginName", "Unknown Vulnerability")
            port = item.get("port", "0")
            proto = item.get("protocol", "tcp")
            svc_name = item.get("svc_name", "general")

            # Extract Exploitability & Threat Intel Tags
            has_exploit = item.find("exploit_available") is not None and item.find("exploit_available").text == "true"
            msf_exploit = item.find("exploit_framework_metasploit") is not None and item.find("exploit_framework_metasploit").text == "true"
            cve_elements = item.findall("cve")
            cves = [c.text for c in cve_elements if c.text]
            cvss3 = item.find("cvss3_base_score")
            cvss_score = cvss3.text if cvss3 is not None else item.findtext("cvss_base_score", "N/A")

            # Update Host Counters
            sev_label = {4: "critical", 3: "high", 2: "medium"}.get(severity, "medium")
            host_summary[token][sev_label] += 1
            host_summary[token]["os"] = os_name

            # Group Findings by Plugin ID (Vulnerability Clustering)
            if plugin_id not in vuln_clusters:
                vuln_clusters[plugin_id] = {
                    "plugin_id": plugin_id,
                    "title": plugin_name,
                    "severity_level": sev_label.upper(),
                    "cvss_score": cvss_score,
                    "cves": cves[:5],  # Top 5 CVEs
                    "has_public_exploit": has_exploit,
                    "metasploit_available": msf_exploit,
                    "service": f"{port}/{proto} ({svc_name})",
                    "affected_hosts_count": 0,
                    "affected_host_tokens": [],
                    "synopsis": (item.findtext("synopsis") or "").strip(),
                    "solution": (item.findtext("solution") or "").strip()
                }

            if token not in vuln_clusters[plugin_id]["affected_host_tokens"]:
                vuln_clusters[plugin_id]["affected_host_tokens"].append(token)
                vuln_clusters[plugin_id]["affected_hosts_count"] += 1

    # Format JSON Output
    vuln_list = list(vuln_clusters.values())
    
    # Sort: Public Exploits first, then Severity (Critical -> High -> Medium)
    sev_weight = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
    vuln_list.sort(
        key=lambda x: (x["has_public_exploit"], sev_weight.get(x["severity_level"], 0), x["affected_hosts_count"]),
        reverse=True
    )

    fleet_summary = {
        "metadata": {
            "total_evaluated_hosts": len(host_summary),
            "unique_vulnerability_classes": len(vuln_list),
            "severity_filter_applied": "Medium, High, Critical (Info/Low excluded)"
        },
        "weaponized_or_critical_vulnerabilities": [v for v in vuln_list if v["has_public_exploit"] or v["severity_level"] == "CRITICAL"],
        "systemic_high_medium_vulnerabilities": [v for v in vuln_list if not (v["has_public_exploit"] or v["severity_level"] == "CRITICAL")],
    }

    # Save outputs
    json_out = os.path.join(output_dir, f"{base_name}_nessus_summary.json")
    key_out = os.path.join(output_dir, f"{base_name}_MAPPING_KEY.json")

    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(fleet_summary, f, indent=2)

    with open(key_out, "w", encoding="utf-8") as f:
        json.dump(ip_map, f, indent=2)

    print(f"[+] Clean Nessus summary generated: {json_out}")
    print(f"[+] Total Vulnerable Hosts: {len(host_summary)} | Unique Flaws: {len(vuln_list)}")
    print(f"[+] Local token key saved: {key_out}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nessus_preprocessor.py <scan_file.nessus>")
        sys.exit(1)
    parse_and_sanitize_nessus(sys.argv[1])
