#!/usr/bin/env python3
"""
Nmap Fleet Pre-Processor & Aggregator
- Sanitizes sensitive IPs and hostnames.
- Aggregates identical host profiles into mathematical clusters.
- Isolates unique/outlier ports into a separate bucket.
- Outputs a lightweight, structured JSON file that fits easily in Claude's prompt.
"""

import collections
import json
import os
import sys
import xml.etree.ElementTree as ET

def preprocess_nmap_xml(xml_path, output_dir="processed_scans"):
    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(xml_path))[0]

    tree = ET.parse(xml_path)
    root = tree.getroot()

    ip_map = {}
    host_counter = 1
    
    # Track host profiles: signature -> list of host tokens
    profiles = collections.defaultdict(list)
    port_frequency = collections.defaultdict(int)
    all_hosts = []

    print(f"[*] Processing {xml_path}...")

    for host in root.findall("host"):
        # Check if host is up
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # Extract & Tokenize IP
        real_ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ["ipv4", "ipv6"]:
                real_ip = addr.get("addr")
                break

        if not real_ip:
            continue

        if real_ip not in ip_map:
            token = f"TARGET_HOST_{host_counter:04d}"
            ip_map[real_ip] = token
            host_counter += 1
        else:
            token = ip_map[real_ip]

        # Extract open ports and services
        open_services = []
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                port_id = port.get("portid")
                proto = port.get("protocol")
                service_elem = port.find("service")
                
                svc_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                svc_prod = service_elem.get("product", "") if service_elem is not None else ""
                svc_ver = service_elem.get("version", "") if service_elem is not None else ""
                
                banner = f"{svc_prod} {svc_ver}".strip()
                svc_repr = f"{port_id}/{proto}:{svc_name}" + (f" ({banner})" if banner else "")
                
                open_services.append(svc_repr)
                port_frequency[f"{port_id}/{proto}:{svc_name}"] += 1

        if not open_services:
            continue

        open_services.sort()
        signature = " | ".join(open_services)
        profiles[signature].append(token)
        
        all_hosts.append({
            "token": token,
            "services": open_services
        })

    # Separate Clusters (>= 3 hosts) vs Outliers (< 3 hosts)
    clusters = []
    outliers = []

    for signature, tokens in profiles.items():
        if len(tokens) >= 3:
            clusters.append({
                "count": len(tokens),
                "representative_tokens": tokens[:5],  # Sample first 5
                "all_tokens_range": f"{tokens[0]} - {tokens[-1]} (Total: {len(tokens)})",
                "service_signature": signature
            })
        else:
            for t in tokens:
                outliers.append({
                    "token": t,
                    "services": signature
                })

    # Sort clusters by size
    clusters.sort(key=lambda x: x["count"], reverse=True)

    fleet_summary = {
        "scan_metadata": {
            "total_hosts_up": len(all_hosts),
            "unique_service_profiles": len(profiles),
            "common_archetypes_count": len(clusters),
            "unique_outliers_count": len(outliers)
        },
        "systemic_archetype_clusters": clusters,
        "high_risk_outliers": outliers
    }

    # Save outputs
    json_out_path = os.path.join(output_dir, f"{base_name}_fleet_summary.json")
    key_out_path = os.path.join(output_dir, f"{base_name}_MAPPING_KEY.json")

    with open(json_out_path, "w", encoding="utf-8") as f:
        json.dump(fleet_summary, f, indent=2)

    with open(key_out_path, "w", encoding="utf-8") as f:
        json.dump(ip_map, f, indent=2)

    print(f"[+] Fleet summary JSON generated: {json_out_path}")
    print(f"[+] Total Hosts: {len(all_hosts)} | Archetypes: {len(clusters)} | Outliers: {len(outliers)}")
    print(f"[+] Secure mapping key saved: {key_out_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nmap_preprocessor.py <scan.xml>")
        sys.exit(1)
    preprocess_nmap_xml(sys.argv[1])
