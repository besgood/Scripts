#!/bin/bash

# Scan Recovery Helper
# Manage completed targets and recovery after crashes

COMPLETED_FILE="completed_targets.txt"
IP_USERS_FILE="ip_users.txt"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_status() {
    echo -e "${BLUE}=== Scan Recovery Status ===${NC}"
    echo ""
    
    if [ ! -f "$COMPLETED_FILE" ]; then
        echo -e "${YELLOW}No completed targets file found${NC}"
        echo "This is a fresh start"
        exit 0
    fi
    
    if [ ! -f "$IP_USERS_FILE" ]; then
        echo -e "${RED}Error: $IP_USERS_FILE not found${NC}"
        echo "Run the main scan script first to generate this file"
        exit 1
    fi
    
    total_ips=$(wc -l < "$IP_USERS_FILE")
    completed=$(wc -l < "$COMPLETED_FILE")
    remaining=$((total_ips - completed))
    percent=$((completed * 100 / total_ips))
    
    echo -e "${GREEN}Progress:${NC}"
    echo "  Total IPs:      $total_ips"
    echo "  Completed:      $completed ($percent%)"
    echo "  Remaining:      $remaining"
    echo ""
    
    if [ "$completed" -gt 0 ]; then
        echo -e "${BLUE}Last 5 completed IPs:${NC}"
        tail -5 "$COMPLETED_FILE"
        echo ""
    fi
    
    if [ "$remaining" -gt 0 ]; then
        echo -e "${YELLOW}Next 5 IPs to scan:${NC}"
        # Show IPs that aren't in completed file
        comm -23 <(awk -F: '{print $1}' "$IP_USERS_FILE" | sort) <(sort "$COMPLETED_FILE") | head -5
        echo ""
    fi
}

show_remaining() {
    if [ ! -f "$COMPLETED_FILE" ] || [ ! -f "$IP_USERS_FILE" ]; then
        echo "No scan in progress"
        exit 1
    fi
    
    echo -e "${BLUE}=== Remaining IPs to Scan ===${NC}"
    echo ""
    
    # Get remaining IPs
    comm -23 <(awk -F: '{print $1}' "$IP_USERS_FILE" | sort) <(sort "$COMPLETED_FILE") > remaining_ips.txt
    
    remaining_count=$(wc -l < remaining_ips.txt)
    echo "Total remaining: $remaining_count"
    echo ""
    echo "Saved to: remaining_ips.txt"
}

reset_scan() {
    echo -e "${YELLOW}This will delete all progress and start fresh${NC}"
    read -p "Are you sure? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        echo "Cancelled"
        exit 0
    fi
    
    rm -f "$COMPLETED_FILE" scan_progress.state scan.pause
    echo -e "${GREEN}✓ Progress reset${NC}"
    echo "Next scan will start from beginning"
}

verify_completed() {
    if [ ! -f "$COMPLETED_FILE" ]; then
        echo "No completed targets file"
        exit 1
    fi
    
    echo -e "${BLUE}=== Verifying Completed Targets ===${NC}"
    echo ""
    
    # Check for duplicates
    duplicates=$(sort "$COMPLETED_FILE" | uniq -d)
    if [ -n "$duplicates" ]; then
        echo -e "${RED}Found duplicate entries:${NC}"
        echo "$duplicates"
        echo ""
        echo "Cleaning duplicates..."
        sort -u "$COMPLETED_FILE" > "${COMPLETED_FILE}.tmp"
        mv "${COMPLETED_FILE}.tmp" "$COMPLETED_FILE"
        echo -e "${GREEN}✓ Duplicates removed${NC}"
    else
        echo -e "${GREEN}✓ No duplicates found${NC}"
    fi
    
    # Check for invalid IPs
    echo ""
    echo "Checking IP format..."
    invalid=$(grep -v -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' "$COMPLETED_FILE")
    if [ -n "$invalid" ]; then
        echo -e "${YELLOW}Warning: Found non-standard entries:${NC}"
        echo "$invalid"
    else
        echo -e "${GREEN}✓ All entries are valid IP addresses${NC}"
    fi
    
    echo ""
    total=$(wc -l < "$COMPLETED_FILE")
    echo "Total valid completed IPs: $total"
}

backup_progress() {
    timestamp=$(date +%Y%m%d_%H%M%S)
    backup_dir="backup_${timestamp}"
    
    mkdir -p "$backup_dir"
    
    [ -f "$COMPLETED_FILE" ] && cp "$COMPLETED_FILE" "$backup_dir/"
    [ -f "$IP_USERS_FILE" ] && cp "$IP_USERS_FILE" "$backup_dir/"
    [ -f "scan_progress.state" ] && cp "scan_progress.state" "$backup_dir/"
    
    echo -e "${GREEN}✓ Progress backed up to: $backup_dir/${NC}"
    echo ""
    echo "Contents:"
    ls -lh "$backup_dir/"
}

show_help() {
    echo "Scan Recovery Helper"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  status        Show scan progress and status"
    echo "  remaining     List all remaining IPs to scan"
    echo "  verify        Check completed targets file for issues"
    echo "  reset         Delete all progress and start fresh"
    echo "  backup        Backup current progress"
    echo "  help          Show this help"
    echo ""
    echo "Files:"
    echo "  completed_targets.txt  - IPs that have been scanned"
    echo "  ip_users.txt          - All IPs with their users"
    echo "  scan_progress.state   - Current scan position"
    echo ""
    echo "Examples:"
    echo "  $0 status              # Check progress"
    echo "  $0 remaining           # See what's left"
    echo "  $0 backup              # Backup before risky operation"
}

# Main logic
case "$1" in
    status)
        show_status
        ;;
    remaining)
        show_remaining
        ;;
    verify)
        verify_completed
        ;;
    reset)
        reset_scan
        ;;
    backup)
        backup_progress
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
