#!/bin/bash
# Security Audit Tool
# Author: Security Engineer
# Version: 2.1
# Purpose: Comprehensive system security audit and vulnerability assessment

set -euo pipefail  # Strict mode: exit on error, undefined vars, pipe failures

# Configuration
AUDIT_DIR="/var/log/security_audit"
REPORT_FILE="$AUDIT_DIR/security_audit_$(date +%Y%m%d_%H%M%S).md"
TEMP_DIR="$AUDIT_DIR/temp"
LOG_FILE="$AUDIT_DIR/audit.log"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

# Create directories
mkdir -p "$AUDIT_DIR" "$TEMP_DIR"

log_message() {
    local level="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message "ERROR" "This script requires root privileges for comprehensive audit"
        echo "Some checks will run, but full audit requires sudo"
    fi
}

gather_system_info() {
    log_message "INFO" "Gathering system information..."

    cat > "$TEMP_DIR/system_info.txt" << EOF
## System Information
**Hostname:** $(hostname)
**Kernel:** $(uname -r)
**Architecture:** $(uname -m)
**Distribution:** $(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown")
**Uptime:** $(uptime -p)
**Current User:** $(whoami)
**Audit Time:** $(date)
EOF
}

check_user_accounts() {
    log_message "INFO" "Auditing user accounts..."

    # Find users with UID < 1000 (system accounts)
    awk -F: '($3 < 1000) && ($7 != "/sbin/nologin") && ($7 != "/bin/false") {print $1,$3,$7}' /etc/passwd > "$TEMP_DIR/suspicious_users.txt"

    # Check for empty password fields
    passwd -Sa | awk -F: '$2 == "" {print $1}' > "$TEMP_DIR/empty_passwords.txt" 2>/dev/null || true

    # List users with shell access
    awk -F: '($7 ~ /bash|sh|zsh|ksh/) {print $1,$6,$7}' /etc/passwd > "$TEMP_DIR/shell_users.txt"
}

analyze_ssh_config() {
    log_message "INFO" "Analyzing SSH configuration..."
    SSH_CONFIG="/etc/ssh/sshd_config"

    if [[ -f "$SSH_CONFIG" ]]; then
        cat > "$TEMP_DIR/ssh_audit.txt" << EOF
### SSH Configuration Analysis
$(grep -E "^(PermitRootLogin|PasswordAuthentication|X11Forwarding|MaxAuthTries)" "$SSH_CONFIG" || echo "Configuration lines not found")
EOF

        # Check for weak settings
        if grep -q "PermitRootLogin yes" "$SSH_CONFIG"; then
            log_message "WARNING" "SSH: PermitRootLogin is enabled"
        fi
        if grep -q "PasswordAuthentication yes" "$SSH_CONFIG"; then
            log_message "WARNING" "SSH: PasswordAuthentication is enabled (consider key‑only)"
        fi
    else
        log_message "ERROR" "SSH configuration file not found: $SSH_CONFIG"
    fi
}

scan_open_ports() {
    log_message "INFO" "Scanning open network ports..."

    # Use ss or netstat for listening ports
    if command -v ss &> /dev/null; then
        ss -tunlp > "$TEMP_DIR/open_ports.txt"
    else
        netstat -tunlp 2>/dev/null > "$TEMP_DIR/open_ports.txt" || true
    fi

    # Count listening services
    LISTENING_COUNT=$(grep -c "LISTEN" "$TEMP_DIR/open_ports.txt")
    log_message "INFO" "Found $LISTENING_COUNT listening services"
}

check_file_permissions() {
    log_message "INFO" "Checking critical file permissions..."

    # Check /etc/shadow
    SHADOW_PERMS=$(stat -c "%a" /etc/shadow 2>/dev/null)
    if [[ "$SHADOW_PERMS" != "600" && "$SHADOW_PERMS" != "000" ]]; then
        log_message "ALERT" "/etc/shadow has weak permissions: $SHADOW_PERMS (should be 600)"
    fi

    # Check world‑writable files in critical directories
    find /etc /var /home -xdev -type f -perm /o+w -ls 2>/dev/null > "$TEMP_DIR/world_writable.txt" || true
}

audit_cron_jobs() {
    log_message "INFO" "Auditing cron jobs..."

    # System cron jobs
    crontab -l 2>/dev/null > "$TEMP_DIR/user_cron.txt" || echo "No user cron jobs" > "$TEMP_DIR/user_cron.txt"
    cat /etc/crontab > "$TEMP_DIR/system_cron.txt" 2>/dev/null || echo "No system cron" > "$TEMP_DIR/system_cron.txt"
}

check_package_updates() {
    log_message "INFO" "Checking for available package updates..."

    if command -v apt &> /dev/null; then
        apt list --upgradable 2>/dev/null > "$TEMP_DIR/upgradable_packages.txt" || true
    elif command -v yum &> /dev/null; then
        yum check-update 2>&1 > "$TEMP_DIR/upgradable_packages.txt" || true
    else
        log_message "INFO" "Package manager not detected or supported"
    fi
}

generate_markdown_report() {
    log_message "INFO" "Generating Markdown security audit report..."

    cat > "$REPORT_FILE" << EOF
# Security Audit Report
**Generated:** $(date)
**System:** $(hostname)

$(cat "$TEMP_DIR/system_info.txt")

## User Account Audit
### Suspicious Accounts (UID < 1000 with shell)
$(if [ -s "$TEMP_DIR/suspicious_users.txt" ]; then
    echo "| Username | UID | Shell |"
    echo "|--------|-----|-------|"
    while read -r user uid shell; do
        echo "| $user | $uid | $shell |"
    done < "$TEMP_DIR/suspicious_users.txt"
else
    echo "*No suspicious accounts found*"
fi)

### Users with Empty Passwords
$(if [ -s "$TEMP_DIR/empty_passwords.txt" ]; then
    cat "$TEMP_DIR/empty_passwords.txt" | sed 's/^/* /'
else
    echo "*No users with empty passwords*"
fi)

## SSH Configuration
$(cat "$TEMP_DIR/ssh_audit.txt")

## Network Services
**Open Ports and Listening Services:**
$(head -20 "$TEMP_DIR/open_ports.txt" | while read line; do
    echo "    $line"
done)

## File System Security
### World‑Writable Files in Critical Directories
$(if [ -s "$TEMP_DIR/world_writable.txt" ]; then
    head -15 "$TEMP_DIR/world_writable.txt" | while read -r line; do
        echo "    $line"
    done
else
    echo "*No world‑writable files found in critical directories*"
fi)

## Scheduled Tasks
### User Cron Jobs
$(cat "$TEMP_DIR/user_cron.txt" | while read -r line; do
    echo "    $line"
done)
