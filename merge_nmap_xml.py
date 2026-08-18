#!/usr/bin/env python3
import xml.etree.ElementTree as ET
from pathlib import Path
import sys

def merge_xml_files(input_dir, output_file):
    xml_files = list(Path(input_dir).glob("*.xml"))
    if not xml_files:
        print("[-] No XML files found to merge.")
        return

    first_tree = ET.parse(xml_files[0])
    root = first_tree.getroot()

    # Append host elements from subsequent XML files
    for xml_file in xml_files[1:]:
        tree = ET.parse(xml_file)
        for host in tree.getroot().findall("host"):
            root.append(host)

    first_tree.write(output_file, encoding="utf-8", xml_declaration=True)
    print(f"[+] Successfully merged {len(xml_files)} XML files into '{output_file}'")

if __name__ == "__main__":
    merge_xml_files("phase2_xml_results", "consolidated_nmap_results.xml")
