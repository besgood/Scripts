#!/usr/bin/env python3
"""
Reverse Token Remapper
Swaps TARGET_HOST_XXXX and TARGET_DOMAIN_XXXX back to actual enterprise IPs/names.
"""
import json, re, sys

def remap_report(report_path, key_path, output_path):
    with open(key_path, "r", encoding="utf-8") as f:
        mapping = json.load(f)
    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Invert the map: token -> real_ip
    inverted_map = {v: k for k, v in mapping.items()}

    # Replace tokens
    for token, real_val in sorted(inverted_map.items(), key=lambda x: len(x[0]), reverse=True):
        content = re.sub(r'\b' + re.escape(token) + r'\b', real_val, content)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Re-identified final report generated: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python remapper.py <claude_report.md> <mapping_key.json> <final_report.md>")
        sys.exit(1)
    remap_report(sys.argv[1], sys.argv[2], sys.argv[3])
