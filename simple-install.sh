#!/bin/bash
# Simplified Installation Script for IP Blacklist Manager
# Works with UFW, CrowdSec, and Docker

set -euo pipefail

SCRIPT_DIR="/opt/blacklist-manager"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Install required packages
install_packages() {
    log "Installing required packages..."
    
    apt update
    apt install -y curl nftables cron
    
    # Enable services
    systemctl enable nftables cron
    systemctl start cron
    
    # Ensure nftables is running
    if ! systemctl is-active --quiet nftables; then
        systemctl start nftables
    fi
    
    log "Packages installed and services enabled"
}

# Create directory and install scripts
install_scripts() {
    log "Installing blacklist management scripts..."
    
    mkdir -p "$SCRIPT_DIR"
    chmod 755 "$SCRIPT_DIR"
    
    # Main blacklist script
    if [[ -f "simplified-blacklist.sh" ]]; then
        cp "simplified-blacklist.sh" "$SCRIPT_DIR/update-blacklists.sh"
    else
        error "Main script 'simplified-blacklist.sh' not found in current directory"
        exit 1
    fi
    
    # Management helper script
    if [[ -f "blacklist-helper.sh" ]]; then
        cp "blacklist-helper.sh" "$SCRIPT_DIR/blacklist-helper.sh"
    else
        error "Helper script 'blacklist-helper.sh' not found in current directory"
        exit 1
    fi
    
    # Make scripts executable
    chmod +x "$SCRIPT_DIR"/*.sh
    chown root:root "$SCRIPT_DIR"/*.sh
    
    # Create convenience symlinks
    ln -sf "$SCRIPT_DIR/blacklist-helper.sh" /usr/local/bin/blacklist
    
    log "Scripts installed successfully"
    log "You can now use 'blacklist' command to manage custom IPs"
}

# Setup log rotation
setup_logrotate() {
    log "Setting up log rotation..."
    
    cat > /etc/logrotate.d/blacklist-manager << 'EOF'
/var/log/blacklist-manager.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
    postrotate
        # Signal any processes if needed
    endscript
}
EOF

    log "Log rotation configured"
}

# Setup cron job
setup_cron() {
    log "Setting up weekly cron job..."
    
    # Cron job runs every Sunday at 3 AM with random delay
    local cron_command="0 3 * * 0 sleep \$((\$RANDOM \% 3600)) && $SCRIPT_DIR/update-blacklists.sh >/dev/null 2>&1"
    
    # Remove existing blacklist cron jobs
    crontab -l 2>/dev/null | grep -v "$SCRIPT_DIR" | crontab - 2>/dev/null || true
    
    # Add new cron job
    (crontab -l 2>/dev/null; echo "$cron_command") | crontab -
    
    log "Cron job installed: Weekly on Sunday at 3 AM (with random delay)"
}

# Check system compatibility
check_compatibility() {
    log "Checking system compatibility..."
    
    # Check Ubuntu
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" == "ubuntu" ]]; then
            log "Ubuntu detected: $VERSION"
        else
            warn "Non-Ubuntu system detected: $ID $VERSION"
            warn "Script should still work but may need adjustments"
        fi
    fi
    
    # Check UFW
    if command -v ufw &> /dev/null; then
        if ufw status | grep -q "Status: active"; then
            log "UFW is active - will integrate with UFW's nftables"
        else
            log "UFW installed but not active - will use standalone mode"
        fi
    else
        log "UFW not found - will use standalone nftables mode"
    fi
    
    # Check CrowdSec
    if systemctl is-active --quiet crowdsec 2>/dev/null; then
        log "CrowdSec is running - perfect compatibility"
    else
        log "CrowdSec not detected (optional)"
    fi
    
    # Check Docker
    if command -v docker &> /dev/null; then
        if systemctl is-active --quiet docker 2>/dev/null; then
            log "Docker is running - container protection enabled"
        else
            log "Docker installed but not running"
        fi
    else
        log "Docker not found (optional)"
    fi
}

# Create initial nftables structure if needed
setup_initial_nftables() {
    log "Setting up initial nftables structure..."
    
    # Only create basic structure if no UFW
    if ! ufw status | grep -q "Status: active" 2>/dev/null; then
        log "Creating basic nftables structure (no UFW detected)"
        
        # Create basic table and chains if they don't exist
        nft add table inet filter 2>/dev/null || true
        
        # Only create chains if they don't exist
        if ! nft list chain inet filter input &>/dev/null; then
            nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'
            log "Created INPUT chain"
        fi
        
        if ! nft list chain inet filter forward &>/dev/null; then
            nft add chain inet filter forward '{ type filter hook forward priority 0; policy accept; }'
            log "Created FORWARD chain"
        fi
    else
        log "UFW is active - using UFW's nftables structure"
    fi
}

# Run initial blacklist update
initial_run() {
    log "Running initial blacklist update..."
    
    if "$SCRIPT_DIR/update-blacklists.sh"; then
        log "Initial blacklist update completed successfully"
    else
        warn "Initial blacklist update failed - check logs"
        warn "You can run it manually later: $SCRIPT_DIR/update-blacklists.sh"
    fi
}

# Show final status and usage instructions
show_usage() {
    log "Installation completed successfully!"
    echo
    echo "=== Usage Instructions ==="
    echo
    echo "📋 Basic Commands:"
    echo "  blacklist add 81.30.0.0/16      # Block subnet (your example)"
    echo "  blacklist add 1.2.3.4           # Block single IP"
    echo "  blacklist remove 81.30.0.0/16   # Remove block"
    echo "  blacklist list                  # Show all blocked IPs"
    echo "  blacklist status                # Show system status"
    echo
    echo "🔧 Management Commands:"
    echo "  sudo $SCRIPT_DIR/update-blacklists.sh     # Manual update"
    echo "  sudo tail -f /var/log/blacklist-manager.log  # View logs"
    echo "  crontab -l | grep blacklist             # Check cron schedule"
    echo
    echo "⚡ Key Features:"
    echo "  ✅ Custom IPs (like 81.30.0.0/16) persist through updates"
    echo "  ✅ Protects both host and Docker containers"
    echo "  ✅ Works with UFW, CrowdSec, and Docker"
    echo "  ✅ Weekly automatic updates via cron"
    echo "  ✅ Simple management with 'blacklist' command"
    echo
    
    # Show current status
    echo "📊 Current Status:"
    if command -v blacklist &>/dev/null; then
        blacklist status 2>/dev/null || warn "Run initial update to see status"
    fi
    
    echo
    warn "Next Steps:"
    echo "1. Add your custom IP ranges: blacklist add 81.30.0.0/16"
    echo "2. Test the blocking works as expected"
    echo "3. Monitor logs during first few runs"
}

# Main installation
main() {
    echo "IP Blacklist Manager - Simplified Installation"
    echo "============================================="
    echo
    
    check_root
    check_compatibility
    echo
    
    install_packages
    install_scripts
    setup_initial_nftables
    setup_logrotate
    setup_cron
    echo
    
    read -p "Run initial blacklist update now? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        log "Skipping initial update - you can run it later"
    else
        initial_run
    fi
    echo
    
    show_usage
}

main "$@"
