#!/bin/bash

# IP Blacklist Manager for nftables
# Automatically downloads and manages IP blacklists from reputable sources
# Compatible with UFW, CrowdSec, and Docker containers
#
# Author: Blacklist Security System
# Version: 1.0
# License: MIT
# Repository: https://github.com/your-repo/ip-blacklist-manager

set -euo pipefail

# Set PATH for cron compatibility
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Configuration
LOG_FILE="/var/log/blacklist-manager.log"
BLACKLIST_SET="blacklist_ips"
NFTABLES_TABLE="inet filter"
TEMP_DIR="/tmp/bl$$"

# Blacklist sources - reputable public threat intelligence
declare -A BLACKLIST_SOURCES=(
    ["spamhaus_drop"]="https://www.spamhaus.org/drop/drop.txt"
    ["feodo"]="https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
    ["emerging_threats"]="https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
)

# Logging function with timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Cleanup function
cleanup() {
    [[ -d "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Check prerequisites
check_requirements() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR: Must run as root"
        exit 1
    fi
    
    for tool in nft curl; do
        if ! command -v "$tool" &> /dev/null; then
            log "ERROR: Missing required tool: $tool"
            exit 1
        fi
    done
    
    mkdir -p "$TEMP_DIR"
}

# Download and process blacklists with robust error handling
download_and_process() {
    log "Starting blacklist download and processing"
    
    # Ensure table and set exist
    nft add table inet filter 2>/dev/null || true
    nft add set inet filter blacklist_ips '{ type ipv4_addr; flags interval; auto-merge; }' 2>/dev/null || true
    
    # Download and load Spamhaus DROP list (high-quality spam/malware networks)
    log "Downloading and loading Spamhaus DROP list..."
    local spamhaus_count=0
    curl -s -m 30 "https://www.spamhaus.org/drop/drop.txt" | \
        grep -v '^;' | \
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' | \
        while read -r ip; do
            if [[ -n "$ip" ]]; then
                if nft add element inet filter blacklist_ips "{ $ip }" 2>/dev/null; then
                    spamhaus_count=$((spamhaus_count + 1))
                    # Progress indicator every 100 IPs
                    if [[ $((spamhaus_count % 100)) -eq 0 ]]; then
                        echo "$(date '+%Y-%m-%d %H:%M:%S') - Progress: $spamhaus_count Spamhaus networks loaded" | tee -a "$LOG_FILE"
                    fi
                fi
            fi
        done
    
    # Download and load Feodo Tracker (banking trojan C&C servers)
    log "Downloading and loading Feodo Tracker botnet IPs..."
    curl -s -m 30 "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt" | \
        grep -v '^#' | \
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
        while read -r ip; do
            if [[ -n "$ip" ]]; then
                nft add element inet filter blacklist_ips "{ $ip }" 2>/dev/null || true
            fi
        done
    
    # Download and load sample from Emerging Threats (various threat categories)
    log "Downloading and loading Emerging Threats sample..."
    curl -s -m 30 "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt" | \
        grep -v '^#' | \
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' | \
        head -200 | \
        while read -r ip; do
            if [[ -n "$ip" ]]; then
                nft add element inet filter blacklist_ips "{ $ip }" 2>/dev/null || true
            fi
        done
}

# Create blocking rules for comprehensive protection
create_blocking_rules() {
    log "Creating blocking rules for host and container protection..."
    
    local rules_created=0
    
    # INPUT chain rule (protects host services)
    if nft list chain inet filter input &>/dev/null; then
        if ! nft list chain inet filter input | grep -q 'blacklist_ips.*drop'; then
            if nft add rule inet filter input ip saddr @blacklist_ips counter drop comment "ip-blacklist" 2>/dev/null; then
                log "Created INPUT chain blocking rule (host protection)"
                ((rules_created++))
            fi
        else
            log "INPUT chain blocking rule already exists"
            ((rules_created++))
        fi
    fi
    
    # FORWARD chain rule (protects Docker containers)
    if nft list chain inet filter forward &>/dev/null; then
        if ! nft list chain inet filter forward | grep -q 'blacklist_ips.*drop'; then
            if nft add rule inet filter forward ip saddr @blacklist_ips counter drop comment "ip-blacklist" 2>/dev/null; then
                log "Created FORWARD chain blocking rule (container protection)"
                ((rules_created++))
            fi
        else
            log "FORWARD chain blocking rule already exists"
            ((rules_created++))
        fi
    fi
    
    log "Blocking rules status: $rules_created rules active"
}

# Generate comprehensive status report
generate_status_report() {
    local total_ips
    total_ips=$(nft list set inet filter blacklist_ips 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' | wc -l || echo "0")
    
    log "=== Blacklist Update Complete ==="
    log "Total blocked networks: $total_ips"
    log "Host protection: $(nft list chain inet filter input | grep -q blacklist_ips && echo "Active" || echo "Inactive")"
    log "Container protection: $(nft list chain inet filter forward | grep -q blacklist_ips && echo "Active" || echo "Inactive")"
    log "Next update: Weekly via cron (Sundays at 3 AM)"
    log "Management: Use 'blacklist' command for manual operations"
    log "================================="
    
    # Check for Docker integration
    if systemctl is-active --quiet docker 2>/dev/null; then
        log "INFO: Docker detected - containers are protected via FORWARD chain"
    fi
    
    # Performance note
    if [[ $total_ips -gt 1000 ]]; then
        log "INFO: Large blacklist loaded efficiently using nftables interval sets"
    fi
}

# Main execution function
main() {
    log "Starting IP blacklist update (Production v1.0)"
    
    check_requirements
    download_and_process
    create_blocking_rules
    generate_status_report
    
    log "IP blacklist system update completed successfully"
}

# Execute main function
main "$@"
