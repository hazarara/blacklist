#!/bin/bash

# IP Blacklist Manager - Installation Script
# Automatically sets up IP blacklist management system
# Compatible with Ubuntu Server, UFW, CrowdSec, and Docker
#
# Author: Blacklist Security System
# Version: 1.0  
# License: MIT
# Repository: https://github.com/your-repo/ip-blacklist-manager

set -euo pipefail

# Configuration
readonly SCRIPT_DIR="/opt/blacklist-manager"
readonly LOG_FILE="/var/log/blacklist-manager.log"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Output formatting functions
log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
highlight() { echo -e "${BLUE}$1${NC}"; }

# Banner
show_banner() {
    highlight "=============================================="
    highlight "   IP Blacklist Security System Installer   "
    highlight "=============================================="
    echo
    echo "This installer will set up an automated IP blacklist"
    echo "system that protects your server and containers from"
    echo "known malicious networks and IP addresses."
    echo
    echo "Features:"
    echo "• Blocks 1,500+ malicious networks automatically"
    echo "• Protects host and Docker containers"
    echo "• Weekly automatic updates"
    echo "• Custom IP management"
    echo "• UFW and CrowdSec integration"
    echo
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This installer must be run as root"
        echo "Usage: sudo ./install.sh"
        exit 1
    fi
}

# Detect system compatibility
check_compatibility() {
    log "Checking system compatibility..."
    
    # Check OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" == "ubuntu" ]]; then
            log "Ubuntu detected: $VERSION_ID"
            if [[ "${VERSION_ID%%.*}" -lt 20 ]]; then
                warn "Ubuntu version may be too old. Recommended: 20.04+"
            fi
        else
            warn "Non-Ubuntu system detected: $ID"
            warn "System should work but may need adjustments"
        fi
    else
        warn "Cannot detect OS version"
    fi
    
    # Check architecture
    local arch=$(uname -m)
    if [[ "$arch" != "x86_64" && "$arch" != "aarch64" ]]; then
        warn "Unsupported architecture: $arch"
    fi
    
    log "System compatibility check completed"
}

# Install required packages
install_packages() {
    log "Installing required packages..."
    
    # Update package list
    apt update
    
    # Install core packages
    local packages=("curl" "nftables" "cron")
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            log "Installing $package..."
            apt install -y "$package"
        else
            log "$package already installed"
        fi
    done
    
    # Enable and start services
    systemctl enable nftables cron
    systemctl start nftables cron
    
    # Verify nftables is working
    if ! systemctl is-active --quiet nftables; then
        systemctl start nftables
    fi
    
    if ! nft list tables >/dev/null 2>&1; then
        error "nftables is not functioning properly"
        exit 1
    fi
    
    log "Package installation completed"
}

# Create directory structure and install scripts
install_scripts() {
    log "Installing blacklist management scripts..."
    
    # Create directory structure
    mkdir -p "$SCRIPT_DIR"
    mkdir -p "$SCRIPT_DIR/docs"
    chmod 755 "$SCRIPT_DIR"
    
    # Check if scripts exist in current directory
    local scripts=("update-blacklists.sh" "blacklist-helper.sh")
    for script in "${scripts[@]}"; do
        if [[ ! -f "./$script" ]]; then
            error "Script not found: $script"
            error "Please ensure all script files are in the current directory:"
            error "• update-blacklists.sh"
            error "• blacklist-helper.sh"
            error "• install.sh"
            exit 1
        fi
    done
    
    # Install scripts
    cp "update-blacklists.sh" "$SCRIPT_DIR/"
    cp "blacklist-helper.sh" "$SCRIPT_DIR/"
    
    # Set permissions
    chmod +x "$SCRIPT_DIR"/*.sh
    chown root:root "$SCRIPT_DIR"/*.sh
    
    # Create convenient symlink
    ln -sf "$SCRIPT_DIR/blacklist-helper.sh" /usr/local/bin/blacklist
    
    log "Scripts installed successfully"
}

# Setup basic nftables structure
setup_nftables() {
    log "Setting up nftables structure..."
    
    # Check if UFW is active
    local ufw_active=false
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw_active=true
        log "UFW detected and active - integrating with existing configuration"
    else
        log "UFW not active - creating standalone nftables configuration"
        
        # Create basic table and chains if they don't exist
        nft add table inet filter 2>/dev/null || true
        
        # Create chains only if they don't exist
        if ! nft list chain inet filter input &>/dev/null; then
            nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'
            log "Created INPUT chain"
        fi
        
        if ! nft list chain inet filter forward &>/dev/null; then
            nft add chain inet filter forward '{ type filter hook forward priority 0; policy accept; }'
            log "Created FORWARD
