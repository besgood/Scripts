#!/bin/bash
# monitor_scan.sh

while true; do
    clear
    echo "=== NETEXEC SCAN MONITOR ==="
    echo ""
    date
    echo ""
    
    # Progress
    if [ -f "ip_users.txt" ] && [ -f "completed_targets.txt" ]; then
        total=$(wc -l < ip_users.txt)
        done=$(wc -l < completed_targets.txt)
        remaining=$((total - done))
        percent=$((done * 100 / total))
        
        echo "PROGRESS:"
        echo "  Completed: $done / $total ($percent%)"
        echo "  Remaining: $remaining"
        echo ""
    fi
    
    # Successes
    if [ -f targeted_scan_*.log ]; then
        successes=$(grep -c "\[+\]" targeted_scan_*.log 2>/dev/null || echo "0")
        echo "SUCCESSFUL LOGINS: $successes"
        echo ""
        
        if [ "$successes" -gt 0 ]; then
            echo "RECENT SUCCESSES:"
            grep "\[+\]" targeted_scan_*.log | tail -5
            echo ""
        fi
    fi
    
    # Last completed IPs
    if [ -f "completed_targets.txt" ]; then
        echo "LAST 3 COMPLETED IPs:"
        tail -3 completed_targets.txt
        echo ""
    fi
    
    # Scan running?
    if pgrep -f "excel_to_targeted_scan" > /dev/null; then
        echo "STATUS: ✓ SCAN RUNNING"
    else
        echo "STATUS: ✗ SCAN NOT RUNNING"
    fi
    
    sleep 10
done
