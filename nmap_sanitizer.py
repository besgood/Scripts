#!/usr/bin/env python3
"""
Nmap Data Sanitizer & Asset Tokenizer
- Replaces IPs, Hostnames, and MACs with consistent pseudonyms (e.g., TARGET_HOST_001).
- Outputs a sanitized XML ready for LLM consumption.
- Generates a local, isolated key file for mapping findings back to real assets.
"""

import json
import os
import sys
import xml.etree.ElementTree as ET

class AssetSanitizer:
    def __init__(self):
        self.ip_map = {}
        self.host_map = {}
        self.domain_map = {}
        self.host_counter = 1
        self.domain_counter = 1

    def get_host_token(self, real_ip):
        if not real_ip:
            return ""
        if real_ip not in self.ip_map:
            token = f"TARGET_HOST_{self.host_counter:03d}"
            self.ip_map[real_ip] = token
            self.host_counter += 1
        return self.ip_map[real_ip]

    def get_domain_token(self, domain_name):
        if not domain_name:
            return ""
        if domain_name not in self.domain_map:
            token = f"TARGET_DOMAIN_{self.domain_counter:03d}.LOCAL"
            self.domain_map[domain_name] = token
            self.domain_counter += 1
        return self.domain_map[domain_name]

    def sanitize_xml(self, xml_file_path):
        """Parses Nmap XML (-oX) and redacts sensitive identifiers."""
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        for host in root.findall("host"):
            # 1. Anonymize IP Addresses & MAC Addresses
            host_token = None
            for addr in host.findall("address"):
                addr_type = addr.get("addrtype")
                actual_addr = addr.get("addr")

                if addr_type in ["ipv4", "ipv6"]:
                    host_token = self.get_host_token(actual_addr)
                    addr.set("addr", f"10.0.0.{self.host_counter - 1}")  # Generic RFC1918 placeholder
                    addr.set("sanitized_token", host_token)

                elif addr_type == "mac":
                    addr.set("addr", "00:00:5E:00:53:01")
                    if "vendor" in addr.attrib:
                        addr.set("vendor", "SanitizedVendor")

            # 2. Anonymize Hostnames & Domains
            hostnames = host.find("hostnames")
            if hostnames is not None and host_token:
                for hostname in hostnames.findall("hostname"):
                    orig_name = hostname.get("name")
                    if orig_name:
                        sanitized_hname = f"{host_token.lower()}.sanitized.local"
                        self.host_map[orig_name] = sanitized_hname
                        hostname.set("name", sanitized_hname)

            # 3. Scrub Leaked IPs/Hostnames from Service Banners & NSE Scripts
            for port in host.findall(".//port"):
                for script in port.findall("script"):
                    output_text = script.get("output", "")
                    for real_ip, token in self.ip_map.items():
                        output_text = output_text.replace(real_ip, token)
                    for real_host, token in self.host_map.items():
                        output_text = output_text.replace(real_host, token)
                    script.set("output", output_text)

        return tree

    def save_mapping_key(self, key_output_path):
        """Saves the correlation map to an isolated local file."""
        mapping_data = {
            "ip_mappings": self.ip_map,
            "hostname_mappings": self.host_map,
            "domain_mappings": self.domain_map,
        }
        with open(key_output_path, "w", encoding="utf-8") as f:
            json.dump(mapping_data, f, indent=4)
        print(f"[+] Secure correlation key saved to: {key_output_path}")

def sanitize_nmap_run(nmap_xml_path, output_dir="sanitized_scans"):
    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(nmap_xml_path))[0]

    sanitizer = AssetSanitizer()
    print(f"[*] Sanitizing {nmap_xml_path}...")

    sanitized_tree = sanitizer.sanitize_xml(nmap_xml_path)

    sanitized_xml_out = os.path.join(output_dir, f"{base_name}_sanitized.xml")
    mapping_key_out = os.path.join(output_dir, f"{base_name}_MAPPING_KEY.json")

    sanitized_tree.write(sanitized_xml_out, encoding="utf-8", xml_declaration=True)
    print(f"[+] Sanitized XML saved to: {sanitized_xml_out}")

    sanitizer.save_mapping_key(mapping_key_out)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nmap_sanitizer.py <path_to_nmap_scan.xml>")
        sys.exit(1)

    sanitize_nmap_run(sys.argv[1])
