#!/usr/bin/env python3
"""
Qualys Linux User Account Parser
Parses cleaned Qualys CSV with IP and Results columns
Outputs IP,Username format for Excel
"""

import csv
import sys
import re

def is_valid_username(username):
    """
    Check if string is a valid Linux username
    """
    if not username:
        return False
    
    # Basic validation: alphanumeric, dash, underscore, period
    # Length between 1-32 characters
    if not re.match(r'^[a-z_][a-z0-9_-]*[$]?$', username, re.IGNORECASE):
        return False
    
    if len(username) > 32:
        return False
    
    return True

def parse_qualys_csv(input_file, output_file=None):
    """
    Parse Qualys CSV and output IP,Username pairs
    """
    output = output_file if output_file else sys.stdout
    
    try:
        with open(input_file, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            
            # Verify required columns exist
            if 'IP' not in reader.fieldnames or 'Results' not in reader.fieldnames:
                print("Error: CSV must have 'IP' and 'Results' columns", file=sys.stderr)
                print(f"Found columns: {reader.fieldnames}", file=sys.stderr)
                return False
            
            # Output header
            if output_file:
                with open(output_file, 'w', newline='') as out:
                    writer = csv.writer(out)
                    writer.writerow(['IP', 'Username'])
                    process_rows(reader, writer)
            else:
                writer = csv.writer(output)
                writer.writerow(['IP', 'Username'])
                process_rows(reader, writer)
            
            return True
            
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return False

def process_rows(reader, writer):
    """
    Process CSV rows and write IP,Username pairs
    """
    row_count = 0
    user_count = 0
    
    for row in reader:
        row_count += 1
        ip = row.get('IP', '').strip()
        results = row.get('Results', '')
        
        if not ip:
            print(f"Warning: Row {row_count} has no IP address", file=sys.stderr)
            continue
        
        if not results:
            print(f"Warning: Row {row_count} ({ip}) has no results", file=sys.stderr)
            continue
        
        # Split results by various newline representations
        # Handle: \n, \r\n, \r, and actual newlines
        results = results.replace('\\r\\n', '\n').replace('\\n', '\n').replace('\r\n', '\n').replace('\r', '\n')
        lines = results.split('\n')
        
        found_users = 0
        for line in lines:
            username = line.strip()
            
            # Skip empty lines
            if not username:
                continue
            
            # Skip obvious non-usernames
            if username.lower() in ['username', 'results', 'user', 'name']:
                continue
            
            # Validate username format
            if is_valid_username(username):
                writer.writerow([ip, username])
                user_count += 1
                found_users += 1
        
        if found_users == 0:
            print(f"Warning: No valid usernames found for {ip}", file=sys.stderr)
    
    print(f"Processed {row_count} IPs, found {user_count} user accounts", file=sys.stderr)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 qualys_parser.py <input.csv> [output.csv]")
        print("")
        print("Input:  CSV with 'IP' and 'Results' columns")
        print("Output: CSV with 'IP' and 'Username' columns (one row per user)")
        print("")
        print("Examples:")
        print("  python3 qualys_parser.py qualys_report.csv > output.csv")
        print("  python3 qualys_parser.py qualys_report.csv output.csv")
        print("")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    success = parse_qualys_csv(input_file, output_file)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
