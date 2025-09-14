#!/bin/bash

# IP Blacklist Management Helper
# Provides user-friendly interface for managing IP blacklists
# Compatible with UFW, CrowdSec, and Docker environments
#
# Author: Blacklist Security System  
# Version: 1.0
# License: MIT
# Repository: https://github.com/your-repo/ip-blacklist-manager

set -euo pipefail

# Configuration
BLACKLIST_SET="blacklist_ips"
NFTABLES_TABLE="inet filter"
LOG_FILE="/var/log/blacklist-manager.log"

# Color codes for output formatting
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - CUSTOM - $1" | tee -a "$LOG_FILE"
}

# Output formatting functions
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
highlight() { echo -e "${BLUE}$1${NC}"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        echo "Usage: sudo blacklist <command>"
        exit 1
    fi
}

# Validate IP address or CIDR notation
validate_ip() {
    local ip="$1"
    
    # Check single IP address (IPv4)
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        # Validate each octet is <= 255
        local IFS='.'
        local ip_array=($ip)
        for octet in "${ip_array[@]}"; do
            if (( octet > 255 )); then
                return 1
            fi
        done
        return 0
    fi
    
    # Check CIDR notation
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        local ip_part="${ip%/*}"
        local cidr="${ip#*/}"
        
        # Validate CIDR range
        if (( cidr > 32 || cidr < 0 )); then
            return 1
        fi
        
        # Validate IP part
        validate_ip "$ip_part"
        return $?
    fi
    
    return 1
}

# Add IP address or CIDR range to blacklist
add_ip() {
    local ip="$1"
    
    # Validate IP format
    if ! validate_ip "$ip"; then
        error "Invalid IP address or CIDR range: $ip"
        echo "Valid formats: 192.168.1.1 or 192.168.0.0/24"
        return 1
    fi
    
    # Check if blacklist set exists
    if ! nft list set "$NFTABLES_TABLE" "$BLACKLIST_SET" &>/dev/null; then
        error "Blacklist set not found"
        echo "Run the main blacklist script first: sudo /opt/blacklist-manager/update-blacklists.sh"
        return 1
    fi
    
    # Check if IP/range is already in blacklist
    if nft list set "$NFTABLES_TABLE" "$BLACKLIST_SET" | grep -q "$ip"; then
        warn "IP/range $ip is already in the blacklist"
        return 0
    fi
    
    # Add IP/range to blacklist
    if nft add element "$NFTABLES_TABLE" "$BLACKLIST_SET" "{ $ip }"; then
        info "Added $ip to blacklist"
        log "Manually added IP/range: $ip"
        
        # Show updated count
        local total
        total=$(nft list set "$NFTABLES_TABLE" "$BLACKLIST_SET" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' | wc -l)
        info "Total blacklisted entries: $total"
        
        return 0
    else
        error "Failed to add $ip to blacklist"
        echo "Check system logs for details: sudo journalctl -n 20"
        return 1
    fi
}

# Remove IP address or CIDR range from blacklist
remove_ip() {
    local ip="$1"
    
    # Validate IP format
    if ! validate_ip "$ip"; then
        error "Invalid IP address or CIDR range: $ip"
        return 1
    fi
    
    # Check if blacklist set exists
    if ! nft list set "$NFTABLES_TABLE" "$BLACKLIST_SET" &>/dev/null; then
        error "Blacklist set not found"
        return 1
    fi
    
    # Check if IP/range is in blacklist
    if ! nft list set "$NFTABLES_TABLE" "$BLACKLIST_SET" | grep -q "$ip"; then
        warn "IP/range $ip is not in the blacklist"
        return 0
    fi
    
    # Remove IP/range from blacklist
    if nft delete element "$NFTABLES_TABLE" "$BLACKLIST_SET" "{ $ip }"; then
        info "Removed $ip from blacklist"
        log "Manually removed IP/range: $ip"
        
        # Show updated count
        local total
        total=$(nft list set "$NFTABLES_TABLE" "$BLACKLIST_SET" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' | wc -l)
        info "Total blacklisted entries: $total"
        
        return 0
    else
        error "Failed to remove $ip from blacklist"
        return 1
    fi
}

# List current blacklist entries
list_blacklist() {
    if ! nft list set "$NFTABLES_TABLE" "$BLACKLIST_SET" &>/dev/null; then
        error "Blacklist set not found"
        echo "Run the main blacklist script first: sudo /opt/blacklist-manager/update-blacklists.sh"
        return 1
    fi
    
    highlight "=== Current Blacklist Entries ==="
    echo
    
    # Extract all IP addresses and ranges
    local entries
    entries=$(nft list set "$NFTABLES_TABLE" "$BLACKLIST_SET" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?')
    
    if [[ -n "$entries" ]]; then
        # Show first 50 entries to avoid overwhelming output
        echo "$entries" | head -50
        
        local total=$(echo "$entries" | wc -l)
        echo
        
        if [[ $total -gt 50 ]]; then
            info "Showing first 50 of $total total entries"
            echo "Use 'sudo nft list set $NFTABLES_TABLE $BLACKLIST_SET' to see all entries"
        else
            info "Total entries: $total"
        fi
        
        # Show breakdown by type
        local single_ips=$(echo "$entries" | grep -v '/' | wc -l)
        local networks=$(echo "$entries" | grep '/' | wc -l)
        info "Breakdown: $single_ips single IPs, $networks networks/ranges"
        
    else
        warn "No entries found in blacklist"
        echo "Add entries with: sudo blacklist add <ip-or-range>"
    fi
}

# Show comprehensive system status
show_status() {
    highlight "=== IP Blacklist System Status ==="
    echo
    
    # Check if blacklist set exists
    if nft list set "$NFTABLES_TABLE" "$BLACKLIST_SET" &>/dev/null; then
        info "Blacklist set: EXISTS"
        
        # Count total entries using correct method
        local count
        count=$(nft list set "$NFTABLES_TABLE" "$BLACKLIST_SET" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' | wc -l)
        info "Total entries: $count"
        
        # Show sample entries
        if [[ $count -gt 0 ]]; then
            info "Sample blocked networks:"
            nft list set "$NFTABLES_TABLE" "$BLACKLIST_SET" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' | head -5 | sed 's/^/  /'
        fi
    else
        error "Blacklist set: NOT FOUND"
        echo "Run: sudo /opt/blacklist-manager/update-blacklists.sh"
        return 1
    fi
    
    echo
    info "Configuration:"
    info "  Table: $NFTABLES_TABLE"
    info "  Set: $BLACKLIST_SET"
    info "  Mode: UFW Integration"
    
    # Check blocking rules status
    echo
    info "Blocking Rules Status:"
    if nft list chain "$NFTABLES_TABLE" input 2>/dev/null | grep -q blacklist_ips; then
        info "  ✅ INPUT chain (host protection): Active"
    else
        warn "  ❌ INPUT chain (host protection): Missing"
        echo "     Fix: sudo nft add rule inet filter input ip saddr @blacklist_ips counter drop comment \"ip-blacklist\""
    fi
    
    if nft list chain "$NFTABLES_TABLE" forward 2>/dev/null | grep -q blacklist_ips; then
        info "  ✅ FORWARD chain (container protection): Active"
    else
        warn "  ❌ FORWARD chain (container protection): Missing"
        echo "     Fix: sudo nft add rule inet filter forward ip saddr @blacklist_ips counter drop comment \"ip-blacklist\""
    fi
    
    # System integration status
    echo
    info "System Integration:"
    
    # Check UFW status
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        info "  ✅ UFW: Active and compatible"
    else
        info "  ℹ️ UFW: Not active (optional)"
    fi
    
    # Check CrowdSec status
    if systemctl is-active --quiet crowdsec 2>/dev/null; then
        info "  ✅ CrowdSec: Active (complementary protection)"
    else
        info "  ℹ️ CrowdSec: Not detected (optional)"
    fi
    
    # Check Docker status
    if command -v docker &>/dev/null && systemctl is-active --quiet docker 2>/dev/null; then
        info "  ✅ Docker: Active (containers protected via FORWARD chain)"
    else
        info "  ℹ️ Docker: Not running (container protection inactive)"
    fi
    
    # Check cron job
    if sudo crontab -l 2>/dev/null | grep -q blacklist; then
        info "  ✅ Auto-updates: Scheduled (weekly)"
        local cron_line=$(sudo crontab -l | grep blacklist)
        info "     Schedule: $cron_line"
    else
        warn "  ❌ Auto-updates: Not scheduled"
        echo "     Fix: Add cron job for weekly updates"
    fi
    
    echo
    # Show recent activity
    if [[ -f "$LOG_FILE" ]]; then
        info "Recent Activity:"
        tail -5 "$LOG_FILE" | sed 's/^/  /'
    fi
}

# Display help information
show_help() {
    highlight "IP Blacklist Management Helper v1.0"
    echo "====================================="
    echo
    echo "USAGE:"
    echo "  sudo blacklist <command> [arguments]"
    echo
    echo "COMMANDS:"
    echo "  add <ip|cidr>      Add IP address or CIDR range to blacklist"
    echo "  remove <ip|cidr>   Remove IP address or CIDR range from blacklist"
    echo "  list               Show current blacklist entries"
    echo "  status             Show comprehensive system status"
    echo "  help               Show this help message"
    echo
    echo "EXAMPLES:"
    echo "  sudo blacklist add 192.168.1.100          # Block single IP"
    echo "  sudo blacklist add 10.0.0.0/8             # Block entire network"
    echo "  sudo blacklist add 81.30.0.0/16           # Block ISP range"
    echo "  sudo blacklist remove 192.168.1.100       # Remove IP block"
    echo "  sudo blacklist list                       # Show blocked networks"
    echo "  sudo blacklist status                     # Full system status"
    echo
    echo "NOTES:"
    echo "  • Custom entries persist through automatic blacklist updates"
    echo "  • Changes take effect immediately"
    echo "  • Both host and Docker containers are protected"
    echo "  • System updates automatically weekly (Sundays at 3 AM)"
    echo
    echo "FILES:"
    echo "  Main script: /opt/blacklist-manager/update-blacklists.sh"
    echo "  Logs: /var/log/blacklist-manager.log"
    echo "  Documentation: /opt/blacklist-manager/docs/"
    echo
    echo "SUPPORT:"
    echo "  • View logs: sudo tail -f /var/log/blacklist-manager.log"
    echo "  • Manual update: sudo /opt/blacklist-manager/update-blacklists.sh"
    echo "  • System status: sudo systemctl status nftables"
}

# Test blocking functionality
test_blocking() {
    local test_ip="$1"
    
    if ! validate_ip "$test_ip"; then
        error "Invalid IP address: $test_ip"
        return 1
    fi
    
    info "Testing blocking for $test_ip..."
    
    # Check if IP is in blacklist
    if nft list set "$NFTABLES_TABLE" "$BLACKLIST_SET" | grep -q "$test_ip"; then
        info "✅ IP $test_ip is in blacklist"
        
        # Test actual blocking
        if timeout 3 ping -c 1 "$test_ip" >/dev/null 2>&1; then
            warn "⚠️  IP responds to ping (may not be blocked or rules inactive)"
        else
            info "✅ IP does not respond (likely blocked successfully)"
        fi
    else
        warn "IP $test_ip is not in blacklist"
    fi
}

# Main execution function
main() {
    check_root
    
    case "${1:-help}" in
        add)
            if [[ -z "${2:-}" ]]; then
                error "Please specify an IP address or CIDR range"
                echo "Example: sudo blacklist add 81.30.0.0/16"
                exit 1
            fi
            add_ip "$2"
            ;;
        remove)
            if [[ -z "${2:-}" ]]; then
                error "Please specify an IP address or CIDR range"
                echo "Example: sudo blacklist remove 81.30.0.0/16"
                exit 1
            fi
            remove_ip "$2"
            ;;
        list)
            list_blacklist
            ;;
        status)
            show_status
            ;;
        test)
            if [[ -z "${2:-}" ]]; then
                error "Please specify an IP address to test"
                echo "Example: sudo blacklist test 1.2.3.4"
                exit 1
            fi
            test_blocking "$2"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            error "Unknown command: ${1:-}"
            echo
            show_help
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"
