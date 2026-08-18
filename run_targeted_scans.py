#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

def parse_gnmap(gnmap_file):
    """Parses gnmap file and groups hosts by open ports."""
    host_ports = {}
    host_re = re.compile(r'^Host:\s+([0-9\.]+)\s+.*?\tPorts:\s+(.+)$')
    port_re = re.compile(r'(\d+)/open/')

    try:
        with open(gnmap_file, 'r') as f:
            for line in f:
                match = host_re.search(line)
                if match:
                    ip = match.group(1)
                    open_ports = port_re.findall(match.group(2))
                    if open_ports:
                        host_ports[ip] = open_ports
    except FileNotFoundError:
        print(f"[-] Error: File '{gnmap_file}' not found.")
        sys.exit(1)
        
    return host_ports

def scan_host(ip, ports, output_dir):
    """Executes targeted Nmap scan for a single host generating XML output."""
    port_str = ",".join(ports)
    output_prefix = Path(output_dir) / f"target_{ip.replace('.', '_')}"
    
    cmd = [
        "nmap",
        "-sC", "-sV",
        "-Pn",
        "--max-rate", "500",      # Controlled rate per thread
        "--host-timeout", "15m",
        "-p", port_str,
        ip,
        "-oX", f"{output_prefix}.xml"
    ]
    
    print(f"[*] Starting targeted scan on {ip} ({len(ports)} open ports)...")
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] Completed {ip}")

def main():
    gnmap_file = "phase1_openports.gnmap"
    output_dir = "phase2_xml_results"
    max_workers = 10  # Number of concurrent host scans
    
    Path(output_dir).mkdir(exist_ok=True)
    targets = parse_gnmap(gnmap_file)
    print(f"[+] Total target hosts with open ports: {len(targets)}")

    # Run second-stage scans concurrently across threads
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(scan_host, ip, ports, output_dir)
            for ip, ports in targets.items()
        ]
        for future in futures:
            future.result()

if __name__ == "__main__":
    main()
