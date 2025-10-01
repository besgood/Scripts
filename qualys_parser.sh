#!/bin/bash

# Qualys Linux User Parser - Simplified for Clean CSV
# Input: CSV with headers "IP" and "Results"
# Results column has usernames separated by newlines
# Output: IP,Username format for Excel

if [ $# -lt 1 ]; then
    echo "Usage: $0 <qualys_report.csv>"
    echo ""
    echo "Input: CSV with 'IP' and 'Results' columns"
    echo "Output: IP,Username (one row per user)"
    echo ""
    echo "Example:"
    echo "  $0 qualys_clean.csv > output.csv"
    exit 1
fi

INPUT_FILE="$1"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: File $INPUT_FILE not found" >&2
    exit 1
fi

# Output header
echo "IP,Username"

# Process the CSV file
# Skip header line, then process each row
tail -n +2 "$INPUT_FILE" | while IFS=',' read -r ip results; do
    # Remove any quotes from IP
    ip=$(echo "$ip" | tr -d '"' | xargs)
    
    # Remove quotes from results field
    results=$(echo "$results" | tr -d '"')
    
    # Split results by actual newlines, \n literals, or other delimiters
    # Handle different newline representations in CSV
    echo "$results" | sed 's/\\n/\n/g' | tr '\r' '\n' | while read -r username; do
        # Clean up username - remove leading/trailing whitespace
        username=$(echo "$username" | xargs)
        
        # Skip empty lines and invalid usernames
        if [ -n "$username" ] && [ "$username" != "Results" ] && [ "$username" != "Username" ]; then
            # Only output valid-looking usernames (alphanumeric, dash, underscore)
            if [[ "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                echo "$ip,$username"
            fi
        fi
    done
done
