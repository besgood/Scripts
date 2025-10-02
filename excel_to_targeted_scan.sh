#!/bin/bash

# Excel to Targeted NetExec Scanner with Pause/Resume & VPN Monitoring
# Converts Excel IP/User columns to optimized scanning
# Prevents SSH service overload by testing users per IP sequentially

EXCEL_FILE="$1"
PASSWORD="$2"
OUTPUT_FORMAT="ip_users.txt"
LOG_FILE="targeted_scan_$(date +%Y%m%d_%H%M%S).log"
SUCCESS_FILE="successful_logins_$(date +%Y%m%d_%H%M%S).txt"
PROGRESS_FILE="scan_progress.state"
COMPLETED_FILE="completed_targets.txt"
PAUSE_FILE="scan.pause"

# VPN Monitoring
VPN_INTERFACE="tun0"     # Change to your VPN interface (tun0, wg0, etc.)
VPN_CHECK_INTERVAL=30    # Check VPN every 30 seconds
VPN_TEST_IP="8.8.8.8"    # IP to test connectivity

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

# Trap Ctrl+C for graceful pause
trap 'handle_interrupt' INT TERM

handle_interrupt() {
    echo ""
    echo -e "${YELLOW}Scan interrupted. Creating pause point...${NC}"
    touch "$PAUSE_FILE"
    echo "Progress saved to: $PROGRESS_FILE"
    echo "To resume, run: $0 --resume"
    exit 0
}

# VPN Check Function
check_vpn() {
    # Check if VPN interface exists
    if ! ip link show "$VPN_INTERFACE" >/dev/null 2>&1; then
        return 1
    fi
    
    # Check if we can reach external IP
    if ! ping -c 1 -W 3 "$VPN_TEST_IP" >/dev/null 2>&1; then
        return 1
    fi
    
    return 0
}

# Wait for VPN reconnection
wait_for_vpn() {
    echo ""
    echo -e "${RED}⚠️  VPN CONNECTION LOST!${NC}"
    echo "Pausing scan and saving progress..."
    echo "$current_ip_index" > "$PROGRESS_FILE"
    
    echo "Waiting for VPN to reconnect..."
    while ! check_vpn; do
        printf "."
        sleep 5
    done
    
    echo ""
    echo -e "${GREEN}✅ VPN reconnected!${NC}"
    echo "Resuming scan in 10 seconds..."
    sleep 10
}

# Check for manual pause
check_manual_pause() {
    if [ -f "$PAUSE_FILE" ]; then
        echo ""
        echo -e "${YELLOW}Manual pause requested...${NC}"
        echo "Progress saved to: $PROGRESS_FILE"
        echo ""
        echo "To resume: $0 --resume"
        echo "To cancel pause: rm $PAUSE_FILE && $0 --resume"
        
        while [ -f "$PAUSE_FILE" ]; do
            sleep 5
        done
        
        echo -e "${GREEN}Resuming scan...${NC}"
    fi
}

# Resume function
resume_scan() {
    if [ ! -f "$OUTPUT_FORMAT" ]; then
        echo -e "${RED}Error: $OUTPUT_FORMAT not found${NC}"
        echo "Cannot resume - input file missing"
        exit 1
    fi
    
    # Check if we have a completed targets file
    if [ -f "$COMPLETED_FILE" ]; then
        completed_count=$(wc -l < "$COMPLETED_FILE")
        echo -e "${GREEN}Found completed targets file${NC}"
        echo "Already completed: $completed_count IPs"
        echo ""
        
        # Show sample of completed
        echo "Sample of completed IPs:"
        head -5 "$COMPLETED_FILE"
        if [ "$completed_count" -gt 5 ]; then
            echo "... and $((completed_count - 5)) more"
        fi
        echo ""
    else
        echo -e "${YELLOW}No completed targets file found - starting from beginning${NC}"
        completed_count=0
        touch "$COMPLETED_FILE"
    fi
    
    # Find the most recent log file
    LOG_FILE=$(ls -t targeted_scan_*.log 2>/dev/null | head -1)
    if [ -z "$LOG_FILE" ]; then
        LOG_FILE="targeted_scan_resumed_$(date +%Y%m%d_%H%M%S).log"
    fi
    
    echo "=== Scan Resumed: $(date) ===" | tee -a "$LOG_FILE"
    echo "Skipping $completed_count completed IPs" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    
    return 0
}

echo -e "${BLUE}=== Excel to Targeted NetExec Scanner ===${NC}"
echo -e "${BLUE}    With Pause/Resume & VPN Monitoring${NC}"
echo ""

# Handle resume flag
start_index=0
if [ "$1" == "--resume" ]; then
    resume_scan
    # Password needed for resume
    if [ -z "$2" ]; then
        read -sp "Enter password: " PASSWORD
        echo ""
    else
        PASSWORD="$2"
    fi
elif [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo "Usage:"
    echo "  New scan:    $0 <excel_file.xlsx|csv> <password>"
    echo "  Resume scan: $0 --resume [password]"
    echo ""
    echo "Features:"
    echo "  - Automatic VPN monitoring and reconnection"
    echo "  - Ctrl+C to pause (saves progress)"
    echo "  - Create '$PAUSE_FILE' file to pause"
    echo "  - Prevents SSH service overload"
    echo ""
    echo "Example:"
    echo "  $0 users.xlsx 'Password123!'"
    echo "  $0 --resume 'Password123!'"
    exit 0
else
    # Check arguments for new scan
    if [ -z "$EXCEL_FILE" ] || [ -z "$PASSWORD" ]; then
        echo "Usage: $0 <excel_file.xlsx|csv> <password>"
        echo "   Or: $0 --resume [password]"
        echo "   Or: $0 --help"
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
        
        if [[ "$EXCEL_FILE" == *.xlsx ]]; then
            if ! python3 -c "import openpyxl" 2>/dev/null; then
                missing="${missing}python3-openpyxl "
            fi
        fi
        
        if [ -n "$missing" ]; then
            echo -e "${RED}Missing dependencies: $missing${NC}"
            echo "Install with: pip3 install openpyxl pandas netexec"
            exit 1
        fi
    }
    
    check_dependencies
    
    echo -e "${YELLOW}Step 1: Converting Excel to IP:users format...${NC}"
    
    # Python script to convert Excel
    python3 - <<EOF "$EXCEL_FILE" "$OUTPUT_FORMAT"
import sys
import pandas as pd
from collections import defaultdict

excel_file = sys.argv[1]
output_file = sys.argv[2]

if excel_file.endswith('.csv'):
    df = pd.read_csv(excel_file)
else:
    df = pd.read_excel(excel_file)

df.columns = df.columns.str.strip().str.lower()

if 'ip' not in df.columns or 'user' not in df.columns:
    print(f"Error: Excel must have 'IP' and 'user' columns")
    print(f"Found columns: {', '.join(df.columns)}")
    sys.exit(1)

ip_users = defaultdict(list)
for _, row in df.iterrows():
    ip = str(row['ip']).strip()
    user = str(row['user']).strip()
    
    if ip and user and ip != 'nan' and user != 'nan':
        if user not in ip_users[ip]:
            ip_users[ip].append(user)

with open(output_file, 'w') as f:
    for ip in sorted(ip_users.keys()):
        users = ','.join(ip_users[ip])
        f.write(f"{ip}:{users}\n")

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
    
    # Verify output file was created
    if [ ! -f "$OUTPUT_FORMAT" ] || [ ! -s "$OUTPUT_FORMAT" ]; then
        echo -e "${RED}Error: Conversion produced empty or missing file${NC}"
        exit 1
    fi
    
    echo ""
    echo -e "${GREEN}✓ Conversion complete${NC}"
    echo -e "  Output file: $OUTPUT_FORMAT"
    echo ""
    
    # Initialize new scan
    touch "$COMPLETED_FILE"
    echo "=== Targeted Scan Started: $(date) ===" | tee "$LOG_FILE"
fi

# VPN Check
echo -e "${YELLOW}Checking VPN connection...${NC}"
if check_vpn; then
    echo -e "${GREEN}✓ VPN connected (${VPN_INTERFACE})${NC}"
else
    echo -e "${YELLOW}⚠ VPN check: Interface $VPN_INTERFACE not found or not connected${NC}"
    echo "Continuing anyway... (edit VPN_INTERFACE in script if needed)"
fi
echo ""

# Main scanning logic
total_ips=$(wc -l < "$OUTPUT_FORMAT")

# Load completed targets if resuming
if [ -f "$COMPLETED_FILE" ]; then
    # Create associative array of completed IPs
    declare -A completed_ips
    while IFS= read -r completed_ip; do
        completed_ips["$completed_ip"]=1
    done < "$COMPLETED_FILE"
fi

echo -e "${BLUE}Step 2: Starting targeted scan...${NC}"
echo -e "${YELLOW}Settings:${NC}"
echo "  Total IPs: $total_ips"
if [ -f "$COMPLETED_FILE" ] && [ "$total_ips" -gt 0 ]; then
    already_done=$(wc -l < "$COMPLETED_FILE")
    remaining=$((total_ips - already_done))
    echo "  Already completed: $already_done"
    echo "  Remaining: $remaining"
fi
echo "  Strategy: Sequential per-IP (prevents SSH overload)"
echo "  Threads: $THREADS"
echo "  Timeout: ${TIMEOUT}s"
echo "  VPN monitoring: Enabled (every ${VPN_CHECK_INTERVAL}s)"
echo ""
echo -e "${YELLOW}Controls:${NC}"
echo "  Ctrl+C: Pause and save progress"
echo "  Create '$PAUSE_FILE': Manual pause"
echo "  VPN disconnect: Auto-pause until reconnect"
echo ""

total_tested=0
total_successes=0
skipped_count=0
last_vpn_check=$(date +%s)

# Process each IP
while IFS=':' read -r ip users_csv; do
    # Skip if already completed
    if [ -n "${completed_ips[$ip]}" ]; then
        skipped_count=$((skipped_count + 1))
        continue
    fi
    
    # Check for manual pause
    check_manual_pause
    
    # Periodic VPN check
    current_time=$(date +%s)
    if [ $((current_time - last_vpn_check)) -ge $VPN_CHECK_INTERVAL ]; then
        if ! check_vpn; then
            wait_for_vpn
        fi
        last_vpn_check=$(date +%s)
    fi
    
    total_tested=$((total_tested + 1))
    progress_num=$((total_tested + skipped_count))
    
    # Convert users to array
    IFS=',' read -ra user_array <<< "$users_csv"
    user_count=${#user_array[@]}
    
    echo -e "${BLUE}[$progress_num/$total_ips] Testing $ip (${user_count} users)${NC}" | tee -a "$LOG_FILE"
    
    # Split users into batches
    for ((i=0; i<${#user_array[@]}; i+=MAX_USERS_PER_BATCH)); do
        batch=("${user_array[@]:i:MAX_USERS_PER_BATCH}")
        batch_size=${#batch[@]}
        batch_num=$((i/MAX_USERS_PER_BATCH + 1))
        total_batches=$(( (user_count + MAX_USERS_PER_BATCH - 1) / MAX_USERS_PER_BATCH ))
        
        if [ $total_batches -gt 1 ]; then
            echo "  Batch $batch_num/$total_batches: ${batch[*]}" | tee -a "$LOG_FILE"
        fi
        
        temp_users=$(mktemp)
        printf "%s\n" "${batch[@]}" > "$temp_users"
        
        netexec ssh "$ip" -u "$temp_users" -p "$PASSWORD" \
            --threads 1 \
            --timeout $TIMEOUT \
            --continue-on-success \
            2>&1 | tee -a "$LOG_FILE" | grep --line-buffered "\[+\]"
        
        if [ $batch_num -lt $total_batches ]; then
            sleep 2
        fi
        
        rm -f "$temp_users"
    done
    
    ip_successes=$(grep "\[+\].*$ip" "$LOG_FILE" | tail -n $user_count | grep -c "\[+\]" || echo "0")
    total_successes=$((total_successes + ip_successes))
    
    if [ "$ip_successes" -gt 0 ]; then
        echo -e "${GREEN}  ✓ $ip: $ip_successes/$user_count successful${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${RED}  ✗ $ip: 0/$user_count successful${NC}" | tee -a "$LOG_FILE"
    fi
    
    # Mark this IP as completed
    echo "$ip" >> "$COMPLETED_FILE"
    
    echo "" | tee -a "$LOG_FILE"
    
done < "$OUTPUT_FORMAT"

# Scan complete - cleanup progress file only (keep completed file)
rm -f "$PROGRESS_FILE" "$PAUSE_FILE"

echo "=== Scan Complete: $(date) ===" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
echo -e "${BLUE}Results Summary:${NC}" | tee -a "$LOG_FILE"
echo "  IPs scanned: $total_tested" | tee -a "$LOG_FILE"
if [ "$skipped_count" -gt 0 ]; then
    echo "  IPs skipped (already done): $skipped_count" | tee -a "$LOG_FILE"
fi
echo "  Successful logins: $total_successes" | tee -a "$LOG_FILE"

if [ "$total_successes" -gt 0 ]; then
    grep "\[+\]" "$LOG_FILE" | grep "SSH" > "$SUCCESS_FILE"
    
    echo "" | tee -a "$LOG_FILE"
    echo -e "${GREEN}Successful Logins:${NC}" | tee -a "$LOG_FILE"
    cat "$SUCCESS_FILE" | tee -a "$LOG_FILE"
    
    echo ""
    echo -e "${GREEN}✓ Success file: $SUCCESS_FILE${NC}"
fi

echo ""
echo "Full log: $LOG_FILE"
echo "Converted data: $OUTPUT_FORMAT"
