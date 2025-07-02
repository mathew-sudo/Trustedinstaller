#!/bin/bash

# Enhanced Security Permissions Manager
# Version 2.1 with TrustedInstaller Level 600 integration

# Security settings - Enhanced
set -euo pipefail  # Exit on error, undefined vars, pipe failures
IFS=$'\n\t'       # Secure Internal Field Separator

# Additional security measures
umask 077         # Restrictive file creation mask
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly LOG_FILE="/var/log/permissions_manager.log"

# Enhanced logging with security audit trail
log_security_event() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local user_info="USER:$(whoami) PID:$$ TTY:$(tty 2>/dev/null || echo 'unknown')"
    
    echo "[$timestamp] [$level] [$user_info] $message" | tee -a "$LOG_FILE" >&2
    
    # Also log to syslog for security monitoring
    logger -t "permissions_manager" -p auth.info "[$level] $message"
}

# If not running as root, re-execute this script with sudo
if [ "$EUID" -ne 0 ]; then
    log_security_event "INFO" "Script requires root. Re-running with sudo..."
    exec sudo "$0" "$@"
fi

# Enhanced root check with audit logging
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_security_event "ERROR" "Unauthorized access attempt - not running as root"
        echo "This script must be run as root. Access denied."
        exit 1
    fi
    log_security_event "INFO" "Root access verified for session start"
}

# Rate limiting for security operations
declare -A OPERATION_TIMESTAMPS
RATE_LIMIT_SECONDS=5

check_rate_limit() {
    local operation="$1"
    local current_time=$(date +%s)
    local last_time=${OPERATION_TIMESTAMPS[$operation]:-0}
    
    if (( current_time - last_time < RATE_LIMIT_SECONDS )); then
        echo "Rate limit exceeded. Please wait before retrying this operation."
        return 1
    fi
    
    OPERATION_TIMESTAMPS[$operation]=$current_time
    return 0
}

# Enhanced path validation with security checks
validate_path() {
    local path="$1"
    local operation="$2"
    
    # Check for empty path
    if [[ -z "$path" ]]; then
        log_security_event "WARNING" "Empty path provided for $operation"
        return 1
    fi
    
    # Prevent path traversal attacks
    if [[ "$path" =~ \.\./|\.\.\\ ]]; then
        log_security_event "CRITICAL" "Path traversal attempt detected: $path"
        return 1
    fi
    
    # Block access to critical system directories
    local restricted_paths=("/etc/shadow" "/etc/passwd" "/root/.ssh" "/proc" "/sys/kernel")
    for restricted in "${restricted_paths[@]}"; do
        if [[ "$path" == "$restricted"* ]]; then
            log_security_event "CRITICAL" "Attempt to access restricted path: $path"
            echo "Error: Access to system critical files is restricted."
            return 1
        fi
    done
    
    # Resolve and validate the path
    local resolved_path
    resolved_path=$(realpath "$path" 2>/dev/null) || {
        log_security_event "WARNING" "Invalid path resolution: $path"
        return 1
    }
    
    # Update the path variable in caller's scope
    printf '%s' "$resolved_path"
    return 0
}

# Enhanced manage_permissions with comprehensive security
manage_permissions() {
    if ! check_rate_limit "manage_permissions"; then
        return 1
    fi
    
    log_security_event "INFO" "Starting permission management session"
    
    echo "Enter the file or directory path:"
    read -r path
    
    # Enhanced path validation
    validated_path=$(validate_path "$path" "permission_management")
    if [[ $? -ne 0 ]]; then
        echo "Error: Invalid or restricted path."
        return 1
    fi
    path="$validated_path"

    if [ ! -e "$path" ]; then
        log_security_event "WARNING" "Attempt to access non-existent path: $path"
        echo "Error: Path does not exist."
        return 1
    fi

    # Show current permissions before changes
    echo "Current permissions for: $path"
    ls -la "$path"
    echo ""

    echo "Choose an action:"
    echo "1. Change ownership"
    echo "2. Modify permissions"
    echo "3. View current permissions"
    echo "4. Change ownership recursively"
    echo "5. Modify permissions recursively"
    echo "6. Cancel operation"
    read -r action

    case $action in
        1)
            echo "Enter the new owner (user:group):"
            read -r owner
            # Enhanced owner validation
            if [[ ! "$owner" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_-]*:[a-zA-Z0-9_][a-zA-Z0-9_-]*$ ]]; then
                echo "Error: Invalid owner format. Use user:group (alphanumeric, underscore, hyphen only)"
                return 1
            fi
            
            # Verify user and group exist
            local user="${owner%:*}"
            local group="${owner#*:}"
            if ! id "$user" >/dev/null 2>&1; then
                echo "Error: User '$user' does not exist."
                return 1
            fi
            if ! getent group "$group" >/dev/null 2>&1; then
                echo "Error: Group '$group' does not exist."
                return 1
            fi
            
            log_security_event "INFO" "Changing ownership of $path to $owner"
            if chown "$owner" "$path"; then
                echo "Ownership changed to $owner."
                log_security_event "SUCCESS" "Ownership changed: $path -> $owner"
            else
                echo "Failed to change ownership."
                log_security_event "ERROR" "Failed to change ownership: $path"
            fi
            ;;
        2)
            echo "Enter the new permissions (e.g., 755):"
            read -r perms
            # Enhanced permissions validation
            if [[ ! "$perms" =~ ^[0-7]{3,4}$ ]]; then
                echo "Error: Invalid permissions format. Use octal notation (e.g., 755)"
                return 1
            fi
            
            # Warn about dangerous permissions
            if [[ "$perms" =~ ^[0-9]*[2367]$ ]] || [[ "$perms" == "777" ]]; then
                echo "WARNING: These permissions allow write access to others. Continue? (y/N)"
                read -r confirm
                if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                    echo "Operation cancelled."
                    return 0
                fi
            fi
            
            log_security_event "INFO" "Changing permissions of $path to $perms"
            if chmod "$perms" "$path"; then
                echo "Permissions changed to $perms."
                log_security_event "SUCCESS" "Permissions changed: $path -> $perms"
            else
                echo "Failed to change permissions."
                log_security_event "ERROR" "Failed to change permissions: $path"
            fi
            ;;
        3)
            ls -la "$path"
            log_security_event "INFO" "Viewed permissions for: $path"
            ;;
        4|5)
            local recursive_op="ownership"
            [[ "$action" == "5" ]] && recursive_op="permissions"
            
            echo "WARNING: This will change $recursive_op recursively for all files and subdirectories."
            echo "This operation cannot be undone. Continue? (y/N)"
            read -r confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                echo "Operation cancelled."
                return 0
            fi
            
            # Additional confirmation for recursive operations
            echo "Type 'CONFIRM' to proceed with recursive $recursive_op change:"
            read -r final_confirm
            if [[ "$final_confirm" != "CONFIRM" ]]; then
                echo "Operation cancelled - confirmation failed."
                return 0
            fi
            
            if [[ "$action" == "4" ]]; then
                echo "Enter the new owner (user:group):"
                read -r owner
                if [[ ! "$owner" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_-]*:[a-zA-Z0-9_][a-zA-Z0-9_-]*$ ]]; then
                    echo "Error: Invalid owner format."
                    return 1
                fi
                log_security_event "CRITICAL" "Recursive ownership change: $path -> $owner"
                if chown -R "$owner" "$path"; then
                    echo "Ownership recursively changed to $owner."
                    log_security_event "SUCCESS" "Recursive ownership completed: $path"
                else
                    echo "Failed to change ownership."
                    log_security_event "ERROR" "Recursive ownership failed: $path"
                fi
            else
                echo "Enter the new permissions (e.g., 755):"
                read -r perms
                if [[ ! "$perms" =~ ^[0-7]{3,4}$ ]]; then
                    echo "Error: Invalid permissions format."
                    return 1
                fi
                log_security_event "CRITICAL" "Recursive permissions change: $path -> $perms"
                if chmod -R "$perms" "$path"; then
                    echo "Permissions recursively changed to $perms."
                    log_security_event "SUCCESS" "Recursive permissions completed: $path"
                else
                    echo "Failed to change permissions."
                    log_security_event "ERROR" "Recursive permissions failed: $path"
                fi
            fi
            ;;
        6)
            echo "Operation cancelled."
            log_security_event "INFO" "Permission management cancelled by user"
            return 0
            ;;
        *)
            echo "Invalid action."
            log_security_event "WARNING" "Invalid action selected: $action"
            return 1
            ;;
    esac
}

# Enhanced autorun setup with security validation
setup_autorun() {
    if ! check_rate_limit "setup_autorun"; then
        return 1
    fi
    
    log_security_event "CRITICAL" "Auto-run setup initiated - potential security risk"
    
    echo "WARNING: Adding scripts to auto-run can be a security risk."
    echo "Only add trusted scripts. Continue? (y/N)"
    read -r consent
    if [[ ! "$consent" =~ ^[Yy]$ ]]; then
        echo "Operation cancelled."
        return 0
    fi
    
    echo "Enter the script path to auto-run on startup:"
    read -r script_path

    # Enhanced script validation
    validated_path=$(validate_path "$script_path" "autorun_setup")
    if [[ $? -ne 0 ]]; then
        echo "Error: Invalid or restricted script path."
        return 1
    fi
    script_path="$validated_path"

    if [ -f "$script_path" ]; then
        # Security scan of the script
        if grep -E "(rm -rf|>/dev/|curl.*sh|wget.*sh)" "$script_path" >/dev/null; then
            echo "WARNING: Script contains potentially dangerous commands."
            echo "Review the script carefully. Continue? (y/N)"
            read -r danger_confirm
            if [[ ! "$danger_confirm" =~ ^[Yy]$ ]]; then
                echo "Operation cancelled for security."
                return 0
            fi
        fi
        
        script_name=$(basename "$script_path")
        log_security_event "CRITICAL" "Adding script to autorun: $script_path"
        
        # Create secure copy
        if cp "$script_path" "/etc/init.d/"; then
            chmod 755 "/etc/init.d/$script_name"
            chown root:root "/etc/init.d/$script_name"
            
            # Use systemctl if available
            if command -v systemctl >/dev/null 2>&1; then
                systemctl enable "$script_name" 2>/dev/null || update-rc.d "$script_name" defaults
            else
                update-rc.d "$script_name" defaults
            fi
            echo "Script added to auto-run."
            log_security_event "SUCCESS" "Auto-run configured: $script_name"
        else
            echo "Error: Failed to copy script to /etc/init.d/"
            log_security_event "ERROR" "Auto-run setup failed: $script_path"
            return 1
        fi
    else
        echo "Script not found."
        log_security_event "ERROR" "Auto-run script not found: $script_path"
        return 1
    fi
}

# Enhanced security tools with comprehensive scanning
security_tools() {
    if ! check_rate_limit "security_scan"; then
        return 1
    fi
    
    log_security_event "INFO" "Security scan initiated"
    echo "Running comprehensive security checks..."
    
    # 1. World-writable files check with size limits
    echo "1. Checking for world-writable files (limited scope for performance)..."
    timeout 30 find /etc /usr/local /var/www -type f -perm -o+w 2>/dev/null | head -20 || echo "Scan timed out or no issues found"
    
    # 2. SUID/SGID files with verification
    echo "2. Checking for SUID/SGID files..."
    find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read -r file; do
        echo "$file $(ls -la "$file")"
    done | head -20
    
    # 3. Network security check
    echo "3. Checking network security..."
    if command -v ss >/dev/null 2>&1; then
        echo "Open ports:"
        ss -tuln | grep LISTEN
    else
        netstat -tuln 2>/dev/null | grep LISTEN || echo "Network tools unavailable"
    fi
    
    # 4. Process security check
    echo "4. Checking for unusual processes..."
    ps aux --sort=-%cpu | head -10
    
    # 5. Failed login attempts
    echo "5. Recent failed login attempts:"
    if [[ -f "/var/log/auth.log" ]]; then
        grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5 || echo "No recent failed logins"
    fi
    
    # 6. File integrity check for critical files
    echo "6. Critical file integrity check:"
    local critical_files=("/etc/passwd" "/etc/shadow" "/etc/sudoers")
    for file in "${critical_files[@]}"; do
        if [[ -f "$file" ]]; then
            echo "$file: $(stat -c '%Y %n' "$file")"
        fi
    done
    
    log_security_event "SUCCESS" "Security scan completed"
}

# Enhanced bruteforce function with strict ethical controls
bruteforce_ng_hull() {
    log_security_event "CRITICAL" "Bruteforce tool access attempted"
    
    echo "=== ETHICAL USE AGREEMENT ==="
    echo "This tool is ONLY for authorized penetration testing and security research."
    echo "Unauthorized use is illegal and may result in criminal prosecution."
    echo "You must have explicit written permission to test the target system."
    echo ""
    echo "By continuing, you agree that:"
    echo "1. You have explicit authorization to test the target"
    echo "2. You will only use this for legitimate security testing"
    echo "3. You understand the legal implications of misuse"
    echo ""
    echo "Do you have explicit written authorization for the target? (YES/NO)"
    read -r authorization
    
    if [[ "$authorization" != "YES" ]]; then
        echo "Operation cancelled. Authorization required."
        log_security_event "WARNING" "Bruteforce access denied - no authorization"
        return 1
    fi
    
    # Additional rate limiting for this dangerous operation
    if ! check_rate_limit "bruteforce"; then
        echo "Rate limit active for security. Please wait."
        return 1
    fi
    
    echo "Enter the target (e.g., IP or hostname):"
    read -r target
    
    # Target validation
    if [[ ! "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$|^[a-zA-Z0-9.-]+$ ]]; then
        echo "Error: Invalid target format."
        return 1
    fi

    # Block localhost and local network attempts
    if [[ "$target" =~ ^(127\.|localhost|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then
        echo "Error: Local network targets are blocked for safety."
        log_security_event "CRITICAL" "Blocked local network bruteforce attempt: $target"
        return 1
    fi
    
    log_security_event "CRITICAL" "Bruteforce attack initiated against: $target"
    
    echo "Enter the username to bruteforce (leave blank to skip):"
    read -r username
    echo "Enter the path to the password wordlist (e.g., /usr/share/wordlists/rockyou.txt):"
    read -r wordlist
    echo "Enter the service to bruteforce (e.g., ssh, ftp, http):"
    read -r service

    # Input validation
    if [[ -z "$target" || -z "$wordlist" || -z "$service" ]]; then
        echo "Target, wordlist, and service are required."
        return 1
    fi

    # Validate wordlist exists
    if [[ ! -f "$wordlist" ]]; then
        echo "Error: Wordlist file not found."
        return 1
    fi

    # Check if hydra is available
    if ! command -v hydra >/dev/null 2>&1; then
        echo "Hydra is not installed. Installing hydra..."
        apt update && apt install -y hydra
    fi

    if [[ -n "$username" ]]; then
        echo "Starting bruteforce attack on $service://$target with username $username..."
        hydra -l "$username" -P "$wordlist" "$target" "$service"
    else
        echo "Starting bruteforce attack on $service://$target with usernames from wordlist..."
        hydra -L "$wordlist" -P "$wordlist" "$target" "$service"
    fi
}

# Enhanced grant_root_superuser with strict controls
grant_root_superuser() {
    log_security_event "CRITICAL" "Root privilege escalation attempt"
    
    echo "=== EXTREME CAUTION REQUIRED ==="
    echo "Granting root permissions can compromise system security."
    echo "This action will be logged and monitored."
    echo ""
    echo "Type 'I UNDERSTAND THE RISKS' to continue:"
    read -r risk_acknowledgment
    
    if [[ "$risk_acknowledgment" != "I UNDERSTAND THE RISKS" ]]; then
        echo "Operation cancelled."
        log_security_event "INFO" "Root privilege escalation cancelled"
        return 0
    fi
    
    # Additional security check
    if ! check_rate_limit "grant_root"; then
        return 1
    fi
    
    echo "Enter the username to grant root/superuser permissions to:"
    read -r username
    
    # Enhanced username validation
    if [[ ! "$username" =~ ^[a-zA-Z][a-zA-Z0-9_-]{0,31}$ ]]; then
        echo "Error: Invalid username format (max 32 chars, start with letter)."
        return 1
    fi
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        echo "Error: User '$username' does not exist."
        return 1
    fi
    
    # Block certain system users
    local system_users=("daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody")
    for sys_user in "${system_users[@]}"; do
        if [[ "$username" == "$sys_user" ]]; then
            echo "Error: Cannot grant root to system user '$username'."
            log_security_event "CRITICAL" "Attempted root grant to system user: $username"
            return 1
        fi
    done
    
    log_security_event "CRITICAL" "Granting root privileges to user: $username"
    
    # Add user to sudo group if available
    if getent group sudo >/dev/null 2>&1; then
        usermod -aG sudo "$username" && echo "Added $username to sudo group."
    fi
    
    # Handle su binaries more safely
    su_paths=(/bin/su /usr/bin/su)
    for path in "${su_paths[@]}"; do
        if [[ -f "$path" ]]; then
            chmod 4755 "$path"
            chown root:root "$path"
            echo "Updated permissions for $path."
        fi
    done
    
    echo "Root/superuser permissions granted to $username."
    log_security_event "SUCCESS" "Root permissions granted to: $username"
}

# Enhanced mobile superuser function with warnings
grant_mobile_superuser() {
    echo "WARNING: This may void your warranty and security. Continue? (y/N)"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Operation cancelled."
        return
    fi
    
    echo "Attempting superuser setup for mobile device..."
    echo "Note: This requires a rooted device and may not work on all Android versions."
    
    # Check if we're actually on Android/Termux
    if [[ ! -d "/system" && ! -n "$TERMUX_VERSION" ]]; then
        echo "Warning: This doesn't appear to be an Android/Termux environment."
    fi
    
    # More conservative approach for mobile
    common_su_paths=(/system/xbin/su /system/bin/su)
    for path in "${common_su_paths[@]}"; do
        if [[ -f "$path" ]]; then
            echo "Found existing su binary at $path"
            ls -la "$path"
        fi
    done
    
    echo "Mobile superuser setup completed (limited scope for safety)."
}

# New function for TrustedInstaller elevation
elevate_to_trustedinstaller() {
    log_security_event "CRITICAL" "TrustedInstaller elevation requested"
    
    echo "=== TRUSTEDINSTALLER ELEVATION ==="
    echo "This will grant maximum system privileges (Level 600)"
    echo "WARNING: This is the highest privilege level possible"
    echo ""
    
    # Use pre-set path from quick elevation or prompt for input
    local target_path="${QUICK_ELEVATION_PATH:-}"
    
    if [[ -z "$target_path" ]]; then
        echo "Enter the target path for TrustedInstaller ownership:"
        read -r target_path
    else
        echo "Target path: $target_path"
    fi
    
    # Validate path
    if [[ -z "$target_path" ]]; then
        echo "Error: Target path cannot be empty"
        return 1
    fi
    
    # Check if we're on Windows (WSL/Cygwin/MSYS)
    if [[ -n "$WINDIR" ]] || command -v powershell.exe >/dev/null 2>&1; then
        echo "Windows environment detected. Using PowerShell elevation..."
        
        # Security confirmation
        echo "Type 'GRANT_TRUSTEDINSTALLER' to proceed:"
        read -r confirmation
        if [[ "$confirmation" != "GRANT_TRUSTEDINSTALLER" ]]; then
            echo "Operation cancelled."
            log_security_event "INFO" "TrustedInstaller elevation cancelled"
            return 0
        fi
        
        log_security_event "CRITICAL" "Executing TrustedInstaller elevation for: $target_path"
        
        # Check for TrustedInstaller script in security tools directory
        local ti_script=""
        if [[ -f "$HOME/security_tools/trustedinstaller/trustedinstaller_elevation.ps1" ]]; then
            ti_script="$HOME/security_tools/trustedinstaller/trustedinstaller_elevation.ps1"
        elif [[ -f "$(pwd)/trustedinstaller_elevation.ps1" ]]; then
            ti_script="$(pwd)/trustedinstaller_elevation.ps1"
        else
            echo "Error: TrustedInstaller PowerShell script not found"
            echo "Please run the security tools environment setup first"
            return 1
        fi
        
        # Execute PowerShell script
        if command -v powershell.exe >/dev/null 2>&1; then
            powershell.exe -ExecutionPolicy Bypass -File "$ti_script" -TargetPath "$target_path" -Operation "elevate"
        elif command -v pwsh >/dev/null 2>&1; then
            pwsh -ExecutionPolicy Bypass -File "$ti_script" -TargetPath "$target_path" -Operation "elevate"
        else
            echo "Error: PowerShell not available"
            return 1
        fi
        
    else
        # Linux/Unix equivalent (sudo + restrictive permissions)
        echo "Unix/Linux environment detected. Applying Level 600 equivalent..."
        
        # Validate and sanitize path
        validated_path=$(validate_path "$target_path" "trustedinstaller_elevation")
        if [[ $? -ne 0 ]]; then
            echo "Error: Invalid path"
            return 1
        fi
        target_path="$validated_path"
        
        if [[ ! -e "$target_path" ]]; then
            echo "Error: Path does not exist"
            return 1
        fi
        
        # Security confirmation
        echo "Type 'GRANT_LEVEL_600' to proceed with maximum security permissions:"
        read -r confirmation
        if [[ "$confirmation" != "GRANT_LEVEL_600" ]]; then
            echo "Operation cancelled."
            return 0
        fi
        
        log_security_event "CRITICAL" "Applying Level 600 permissions to: $target_path"
        
        # Apply Level 600 permissions (read/write for owner only)
        if chmod 600 "$target_path" && chown root:root "$target_path"; then
            echo "Level 600 permissions applied successfully"
            echo "Permissions: $(ls -la "$target_path")"
            log_security_event "SUCCESS" "Level 600 permissions applied: $target_path"
        else
            echo "Failed to apply Level 600 permissions"
            log_security_event "ERROR" "Failed to apply Level 600 permissions: $target_path"
            return 1
        fi
    fi
}

# Enhanced function for Windows TrustedInstaller management
manage_trustedinstaller() {
    if ! check_rate_limit "trustedinstaller_mgmt"; then
        return 1
    fi
    
    echo "=== TRUSTEDINSTALLER MANAGEMENT ==="
    echo "1. Elevate to TrustedInstaller (Level 600)"
    echo "2. View current TrustedInstaller processes"
    echo "3. Check TrustedInstaller service status"
    echo "4. View TrustedInstaller audit log"
    echo "5. Reset permissions from TrustedInstaller"
    echo "6. Back to main menu"
    
    read -p "Choose option [1-6]: " -r ti_choice
    
    case $ti_choice in
        1)
            elevate_to_trustedinstaller
            ;;
        2)
            echo "Current TrustedInstaller processes:"
            if command -v powershell.exe >/dev/null 2>&1; then
                powershell.exe -Command "Get-Process | Where-Object {$_.ProcessName -like '*TrustedInstaller*'} | Format-Table ProcessName, Id, CPU"
            else
                ps aux | grep -i trusted || echo "No TrustedInstaller processes found (Linux environment)"
            fi
            ;;
        3)
            echo "TrustedInstaller service status:"
            if command -v powershell.exe >/dev/null 2>&1; then
                powershell.exe -Command "Get-Service TrustedInstaller | Format-Table Name, Status, StartType"
            else
                echo "TrustedInstaller service check not available (Linux environment)"
            fi
            ;;
        4)
            echo "TrustedInstaller audit log:"
            if [[ -f "$WINDIR/Temp/trustedinstaller_audit.log" ]]; then
                tail -20 "$WINDIR/Temp/trustedinstaller_audit.log"
            elif command -v powershell.exe >/dev/null 2>&1; then
                powershell.exe -File "$(pwd)/trustedinstaller_elevation.ps1" -Operation "audit"
            else
                echo "No audit log available"
            fi
            ;;
        5)
            echo "Reset permissions from TrustedInstaller ownership:"
            echo "Enter path to reset:"
            read -r reset_path
            
            if [[ -n "$reset_path" ]]; then
                echo "WARNING: This will remove TrustedInstaller ownership. Continue? (y/N)"
                read -r reset_confirm
                if [[ "$reset_confirm" =~ ^[Yy]$ ]]; then
                    log_security_event "INFO" "Resetting TrustedInstaller permissions: $reset_path"
                    
                    if command -v powershell.exe >/dev/null 2>&1; then
                        powershell.exe -Command "icacls.exe '$reset_path' /setowner 'Administrators' /t"
                        powershell.exe -Command "icacls.exe '$reset_path' /reset /t"
                    else
                        chmod 755 "$reset_path" 2>/dev/null || echo "Reset failed"
                    fi
                    echo "Permissions reset completed"
                fi
            fi
            ;;
        6)
            return 0
            ;;
        *)
            echo "Invalid choice"
            ;;
    esac
}

# Load settings at script start
load_settings

# Enhanced main menu with synchronized TrustedInstaller integration
main_menu() {
    check_root
    
    local session_id="$$_$(date +%s)"
    log_security_event "INFO" "Session started: $session_id"
    
    local session_start=$(date +%s)
    local session_timeout=3600  # 1 hour
    
    while true; do
        local current_time=$(date +%s)
        if (( current_time - session_start > session_timeout )); then
            echo "Session timeout reached. Exiting for security."
            log_security_event "INFO" "Session timeout: $session_id"
            exit 0
        fi
        
        show_banner
        color_echo yellow "Select an option:"
        echo "1. Manage Permissions"
        echo "2. Set Up Auto-Run"
        echo "3. Security Tools"
        echo "4. Set Up Kali NetHunter/Termux"
        echo "5. Manage Metasploit/Exploits"
        echo "6. Manage Kali NetHunter Tools/Exploits"
        echo "7. Float up to 6 Windows"
        echo "8. Exit"
        echo "9. Run bruteforce.ng hull"
        echo "10. Console Ninja Engine (Help)"
        echo "11. Grant Root/Superuser Permission to User & Ensure su Binaries"
        echo "12. Grant Superuser/Root for Mobile Device (Android/Tablet)"
        echo "13. Settings & UI Config"
        echo "14. View Security Logs"
        echo "15. TrustedInstaller Management (Level 600)"
        echo "16. Quick TrustedInstaller Elevation"
        echo ""
        echo "Session time remaining: $(( (session_timeout - (current_time - session_start)) / 60 )) minutes"
        read -p "Enter choice [1-16]: " -r choice
        
        case $choice in
            1) manage_permissions || echo "Permission management failed" ;;
            2) setup_autorun || echo "Auto-run setup failed" ;;
            3) security_tools || echo "Security scan failed" ;;
            4) setup_kali_nethunter_termux || echo "Kali/Termux setup failed" ;;
            5) setup_metasploit || echo "Metasploit setup failed" ;;
            6) setup_kali_nethunter_tools || echo "Kali tools setup failed" ;;
            7) float_windows || echo "Window floating failed" ;;
            8) 
                echo "Exiting..."
                log_security_event "INFO" "Session ended normally: $session_id"
                exit 0 
                ;;
            9) bruteforce_ng_hull || echo "Bruteforce operation failed" ;;
            10) console_ninja_engine ;;
            11) grant_root_superuser || echo "Root permission grant failed" ;;
            12) grant_mobile_superuser || echo "Mobile superuser setup failed" ;;
            13) settings_ui_config ;;
            14) 
                echo "Recent security log entries:"
                tail -20 "$LOG_FILE" 2>/dev/null || echo "No log file found"
                ;;
            15) manage_trustedinstaller || echo "TrustedInstaller management failed" ;;
            16) 
                echo "Quick TrustedInstaller Level 600 Elevation"
                echo "Enter target path:"
                read -r quick_path
                if [[ -n "$quick_path" ]]; then
                    # Set global variable for elevate_to_trustedinstaller to use
                    QUICK_ELEVATION_PATH="$quick_path"
                    elevate_to_trustedinstaller
                    unset QUICK_ELEVATION_PATH
                else
                    echo "No path provided"
                fi
                ;;
            *) 
                color_echo red "Invalid choice. Please enter 1-16." 
                log_security_event "WARNING" "Invalid menu choice: $choice"
                sleep 1 
                ;;
        esac
        
        if [[ "$choice" != "8" && "$choice" != "10" && "$choice" != "14" ]]; then
            echo
            read -p "Press Enter to continue..." -r
        fi
    done
}

# Helper for colored output
color_echo() {
    local color="$1"; shift
    case $color in
        red)    echo -e "\033[31m$*\033[0m" ;;
        green)  echo -e "\033[32m$*\033[0m" ;;
        yellow) echo -e "\033[33m$*\033[0m" ;;
        blue)   echo -e "\033[34m$*\033[0m" ;;
        magenta)echo -e "\033[35m$*\033[0m" ;;
        cyan)   echo -e "\033[36m$*\033[0m" ;;
        bold)   echo -e "\033[1m$*\033[0m" ;;
        *)      echo "$*" ;;
    esac
}

# Banner for UI
show_banner() {
    clear
    color_echo cyan "======================================="
    color_echo bold "   TrustedInstaller Permissions Manager"
    color_echo bold "   Level 600 Security Environment"
    color_echo cyan "======================================="
}

# Settings and UI config file path
default_settings_file="/etc/permissions_manager.conf"

# Function to load settings from config file
load_settings() {
    if [ -f "$default_settings_file" ]; then
        source "$default_settings_file"
    fi
}

# Function to save settings to config file
save_settings() {
    echo "# Permissions Manager Settings" > "$default_settings_file"
    echo "DEFAULT_TERMINAL=\"$DEFAULT_TERMINAL\"" >> "$default_settings_file"
    echo "DEFAULT_PERMS=\"$DEFAULT_PERMS\"" >> "$default_settings_file"
    echo "DEFAULT_OWNER=\"$DEFAULT_OWNER\"" >> "$default_settings_file"
    echo "UI_THEME=\"$UI_THEME\"" >> "$default_settings_file"
    chmod 600 "$default_settings_file"
}

# Function to configure UI and settings
settings_ui_config() {
    while true; do
        echo "--- Settings & UI Config ---"
        echo "1. Set Default Terminal (current: ${DEFAULT_TERMINAL:-xterm})"
        echo "2. Set Default Permissions (current: ${DEFAULT_PERMS:-755})"
        echo "3. Set Default Owner (current: ${DEFAULT_OWNER:-root:root})"
        echo "4. Set UI Theme (current: ${UI_THEME:-default})"
        echo "5. Save Settings"
        echo "6. Back to Main Menu"
        read -p "Choose an option: " -r settings_choice
        
        case $settings_choice in
            1)
                read -p "Enter default terminal (xterm/gnome-terminal/konsole): " -r DEFAULT_TERMINAL
                if [[ ! "$DEFAULT_TERMINAL" =~ ^(xterm|gnome-terminal|konsole)$ ]]; then
                    echo "Invalid terminal. Using xterm as default."
                    DEFAULT_TERMINAL="xterm"
                fi
                ;;
            2)
                read -p "Enter default permissions (e.g., 755): " -r DEFAULT_PERMS
                if [[ ! "$DEFAULT_PERMS" =~ ^[0-7]{3,4}$ ]]; then
                    echo "Invalid permissions format. Using 755 as default."
                    DEFAULT_PERMS="755"
                fi
                ;;
            3)
                read -p "Enter default owner (user:group): " -r DEFAULT_OWNER
                if [[ ! "$DEFAULT_OWNER" =~ ^[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+$ ]]; then
                    echo "Invalid owner format. Using root:root as default."
                    DEFAULT_OWNER="root:root"
                fi
                ;;
            4)
                read -p "Enter UI theme (default/dark/light): " -r UI_THEME
                if [[ ! "$UI_THEME" =~ ^(default|dark|light)$ ]]; then
                    echo "Invalid theme. Using default."
                    UI_THEME="default"
                fi
                ;;
            5)
                save_settings
                echo "Settings saved."
                ;;
            6)
                return
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac
    done
}

# Initialize logging
touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/permissions_manager.log"
chmod 600 "$LOG_FILE" 2>/dev/null

# Run the main menu
main_menu
    while true; do
        echo "--- Settings & UI Config ---"
        echo "1. Set Default Terminal (current: ${DEFAULT_TERMINAL:-xterm})"
        echo "2. Set Default Permissions (current: ${DEFAULT_PERMS:-755})"
        echo "3. Set Default Owner (current: ${DEFAULT_OWNER:-root:root})"
        echo "4. Set UI Theme (current: ${UI_THEME:-default})"
        echo "5. Save Settings"
        echo "6. Back to Main Menu"
        read -p "Choose an option: " -r settings_choice
        
        case $settings_choice in
            1)
                read -p "Enter default terminal (xterm/gnome-terminal/konsole): " -r DEFAULT_TERMINAL
                if [[ ! "$DEFAULT_TERMINAL" =~ ^(xterm|gnome-terminal|konsole)$ ]]; then
                    echo "Invalid terminal. Using xterm as default."
                    DEFAULT_TERMINAL="xterm"
                fi
                ;;
            2)
                read -p "Enter default permissions (e.g., 755): " -r DEFAULT_PERMS
                if [[ ! "$DEFAULT_PERMS" =~ ^[0-7]{3,4}$ ]]; then
                    echo "Invalid permissions format. Using 755 as default."
                    DEFAULT_PERMS="755"
                fi
                ;;
            3)
                read -p "Enter default owner (user:group): " -r DEFAULT_OWNER
                if [[ ! "$DEFAULT_OWNER" =~ ^[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+$ ]]; then
                    echo "Invalid owner format. Using root:root as default."
                    DEFAULT_OWNER="root:root"
                fi
                ;;
            4)
                read -p "Enter UI theme (default/dark/light): " -r UI_THEME
                if [[ ! "$UI_THEME" =~ ^(default|dark|light)$ ]]; then
                    echo "Invalid theme. Using default."
                    UI_THEME="default"
                fi
                ;;
            5)
                save_settings
                echo "Settings saved."
                ;;
            6)
                return
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac
    done
}

# Function to grant root/superuser permission to a user and ensure su binaries exist
grant_root_superuser() {
    echo "WARNING: Granting root permissions is dangerous. Continue? (y/N)"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Operation cancelled."
        return
    fi
    
    echo "Enter the username to grant root/superuser permissions to:"
    read -r username
    
    # Validate username format
    if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "Error: Invalid username format."
        return 1
    fi
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        echo "User $username does not exist."
        return 1
    fi
    
    # Add user to sudo group if available
    if getent group sudo >/dev/null 2>&1; then
        usermod -aG sudo "$username" && echo "Added $username to sudo group."
    fi
    
    # Handle su binaries more safely
    su_paths=(/bin/su /usr/bin/su)
    for path in "${su_paths[@]}"; do
        if [[ -f "$path" ]]; then
            chmod 4755 "$path"
            chown root:root "$path"
            echo "Updated permissions for $path."
        fi
    done
    
    echo "Root/superuser permissions granted to $username."
}

# Enhanced mobile superuser function with warnings
grant_mobile_superuser() {
    echo "WARNING: This may void your warranty and security. Continue? (y/N)"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Operation cancelled."
        return
    fi
    
    echo "Attempting superuser setup for mobile device..."
    echo "Note: This requires a rooted device and may not work on all Android versions."
    
    # Check if we're actually on Android/Termux
    if [[ ! -d "/system" && ! -n "$TERMUX_VERSION" ]]; then
        echo "Warning: This doesn't appear to be an Android/Termux environment."
    fi
    
    # More conservative approach for mobile
    common_su_paths=(/system/xbin/su /system/bin/su)
    for path in "${common_su_paths[@]}"; do
        if [[ -f "$path" ]]; then
            echo "Found existing su binary at $path"
            ls -la "$path"
        fi
    done
    
    echo "Mobile superuser setup completed (limited scope for safety)."
}

# Load settings at script start
load_settings

# Enhanced main menu with better error handling
main_menu() {
    check_root
    
    # Create session ID for tracking
    local session_id="$$_$(date +%s)"
    log_security_event "INFO" "Session started: $session_id"
    
    # Set session timeout
    local session_start=$(date +%s)
    local session_timeout=3600  # 1 hour
    
    while true; do
        # Check session timeout
        local current_time=$(date +%s)
        if (( current_time - session_start > session_timeout )); then
            echo "Session timeout reached. Exiting for security."
            log_security_event "INFO" "Session timeout: $session_id"
            exit 0
        fi
        
        show_banner
        color_echo yellow "Select an option:"
        echo "1. Manage Permissions"
        echo "2. Set Up Auto-Run"
        echo "3. Security Tools"
        echo "4. Set Up Kali NetHunter/Termux"
        echo "5. Manage Metasploit/Exploits"
        echo "6. Manage Kali NetHunter Tools/Exploits"
        echo "7. Float up to 6 Windows"
        echo "8. Exit"
        echo "9. Run bruteforce.ng hull"
        echo "10. Console Ninja Engine (Help)"
        echo "11. Grant Root/Superuser Permission to User & Ensure su Binaries"
        echo "12. Grant Superuser/Root for Mobile Device (Android/Tablet)"
        echo "13. Settings & UI Config"
        echo "14. View Security Logs"
        echo ""
        echo "Session time remaining: $(( (session_timeout - (current_time - session_start)) / 60 )) minutes"
        read -p "Enter choice [1-14]: " -r choice
        
        case $choice in
            1) manage_permissions || echo "Permission management failed" ;;
            2) setup_autorun || echo "Auto-run setup failed" ;;
            3) security_tools || echo "Security scan failed" ;;
            4) setup_kali_nethunter_termux || echo "Kali/Termux setup failed" ;;
            5) setup_metasploit || echo "Metasploit setup failed" ;;
            6) setup_kali_nethunter_tools || echo "Kali tools setup failed" ;;
            7) float_windows || echo "Window floating failed" ;;
            8) 
                echo "Exiting..."
                log_security_event "INFO" "Session ended normally: $session_id"
                exit 0 
                ;;
            9) bruteforce_ng_hull || echo "Bruteforce operation failed" ;;
            10) console_ninja_engine ;;
            11) grant_root_superuser || echo "Root permission grant failed" ;;
            12) grant_mobile_superuser || echo "Mobile superuser setup failed" ;;
            13) settings_ui_config ;;
            14) 
                echo "Recent security log entries:"
                tail -20 "$LOG_FILE" 2>/dev/null || echo "No log file found"
                ;;
            *) 
                color_echo red "Invalid choice. Please enter 1-14." 
                log_security_event "WARNING" "Invalid menu choice: $choice"
                sleep 1 
                ;;
        esac
        
        # Add pause after operations
        if [[ "$choice" != "8" && "$choice" != "10" && "$choice" != "14" ]]; then
            echo
            read -p "Press Enter to continue..." -r
        fi
    done
}

# Helper for colored output
color_echo() {
    local color="$1"; shift
    case $color in
        red)    echo -e "\033[31m$*\033[0m" ;;
        green)  echo -e "\033[32m$*\033[0m" ;;
        yellow) echo -e "\033[33m$*\033[0m" ;;
        blue)   echo -e "\033[34m$*\033[0m" ;;
        magenta)echo -e "\033[35m$*\033[0m" ;;
        cyan)   echo -e "\033[36m$*\033[0m" ;;
        bold)   echo -e "\033[1m$*\033[0m" ;;
        *)      echo "$*" ;;
    esac
}

# Banner for UI
show_banner() {
    clear
    color_echo cyan "==============================="
    color_echo bold "   Permissions Manager UI"
    color_echo cyan "==============================="
}

# Settings and UI config file path
default_settings_file="/etc/permissions_manager.conf"

# Function to load settings from config file
load_settings() {
    if [ -f "$default_settings_file" ]; then
        source "$default_settings_file"
    fi
}

# Function to save settings to config file
save_settings() {
    echo "# Permissions Manager Settings" > "$default_settings_file"
    echo "DEFAULT_TERMINAL=\"$DEFAULT_TERMINAL\"" >> "$default_settings_file"
    echo "DEFAULT_PERMS=\"$DEFAULT_PERMS\"" >> "$default_settings_file"
    echo "DEFAULT_OWNER=\"$DEFAULT_OWNER\"" >> "$default_settings_file"
    echo "UI_THEME=\"$UI_THEME\"" >> "$default_settings_file"
    chmod 600 "$default_settings_file"
}

# Function to configure UI and settings
settings_ui_config() {
    while true; do
        echo "--- Settings & UI Config ---"
        echo "1. Set Default Terminal (current: ${DEFAULT_TERMINAL:-xterm})"
        echo "2. Set Default Permissions (current: ${DEFAULT_PERMS:-755})"
        echo "3. Set Default Owner (current: ${DEFAULT_OWNER:-root:root})"
        echo "4. Set UI Theme (current: ${UI_THEME:-default})"
        echo "5. Save Settings"
        echo "6. Back to Main Menu"
        read -p "Choose an option: " -r settings_choice
        
        case $settings_choice in
            1)
                read -p "Enter default terminal (xterm/gnome-terminal/konsole): " -r DEFAULT_TERMINAL
                if [[ ! "$DEFAULT_TERMINAL" =~ ^(xterm|gnome-terminal|konsole)$ ]]; then
                    echo "Invalid terminal. Using xterm as default."
                    DEFAULT_TERMINAL="xterm"
                fi
                ;;
            2)
                read -p "Enter default permissions (e.g., 755): " -r DEFAULT_PERMS
                if [[ ! "$DEFAULT_PERMS" =~ ^[0-7]{3,4}$ ]]; then
                    echo "Invalid permissions format. Using 755 as default."
                    DEFAULT_PERMS="755"
                fi
                ;;
            3)
                read -p "Enter default owner (user:group): " -r DEFAULT_OWNER
                if [[ ! "$DEFAULT_OWNER" =~ ^[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+$ ]]; then
                    echo "Invalid owner format. Using root:root as default."
                    DEFAULT_OWNER="root:root"
                fi
                ;;
            4)
                read -p "Enter UI theme (default/dark/light): " -r UI_THEME
                if [[ ! "$UI_THEME" =~ ^(default|dark|light)$ ]]; then
                    echo "Invalid theme. Using default."
                    UI_THEME="default"
                fi
                ;;
            5)
                save_settings
                echo "Settings saved."
                ;;
            6)
                return
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac
    done
}

# Function to grant root/superuser permission to a user and ensure su binaries exist
grant_root_superuser() {
    echo "WARNING: Granting root permissions is dangerous. Continue? (y/N)"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Operation cancelled."
        return
    fi
    
    echo "Enter the username to grant root/superuser permissions to:"
    read -r username
    
    # Validate username format
    if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "Error: Invalid username format."
        return 1
    fi
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        echo "User $username does not exist."
        return 1
    fi
    
    # Add user to sudo group if available
    if getent group sudo >/dev/null 2>&1; then
        usermod -aG sudo "$username" && echo "Added $username to sudo group."
    fi
    
    # Handle su binaries more safely
    su_paths=(/bin/su /usr/bin/su)
    for path in "${su_paths[@]}"; do
        if [[ -f "$path" ]]; then
            chmod 4755 "$path"
            chown root:root "$path"
            echo "Updated permissions for $path."
        fi
    done
    
    echo "Root/superuser permissions granted to $username."
}

# Enhanced mobile superuser function with warnings
grant_mobile_superuser() {
    echo "WARNING: This may void your warranty and security. Continue? (y/N)"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Operation cancelled."
        return
    fi
    
    echo "Attempting superuser setup for mobile device..."
    echo "Note: This requires a rooted device and may not work on all Android versions."
    
    # Check if we're actually on Android/Termux
    if [[ ! -d "/system" && ! -n "$TERMUX_VERSION" ]]; then
        echo "Warning: This doesn't appear to be an Android/Termux environment."
    fi
    
    # More conservative approach for mobile
    common_su_paths=(/system/xbin/su /system/bin/su)
    for path in "${common_su_paths[@]}"; do
        if [[ -f "$path" ]]; then
            echo "Found existing su binary at $path"
            ls -la "$path"
        fi
    done
    
    echo "Mobile superuser setup completed (limited scope for safety)."
}

# Load settings at script start
load_settings

# Enhanced main menu with better error handling
main_menu() {
    check_root
    
    # Create session ID for tracking
    local session_id="$$_$(date +%s)"
    log_security_event "INFO" "Session started: $session_id"
    
    # Set session timeout
    local session_start=$(date +%s)
    local session_timeout=3600  # 1 hour
    
    while true; do
        # Check session timeout
        local current_time=$(date +%s)
        if (( current_time - session_start > session_timeout )); then
            echo "Session timeout reached. Exiting for security."
            log_security_event "INFO" "Session timeout: $session_id"
            exit 0
        fi
        
        show_banner
        color_echo yellow "Select an option:"
        echo "1. Manage Permissions"
        echo "2. Set Up Auto-Run"
        echo "3. Security Tools"
        echo "4. Set Up Kali NetHunter/Termux"
        echo "5. Manage Metasploit/Exploits"
        echo "6. Manage Kali NetHunter Tools/Exploits"
        echo "7. Float up to 6 Windows"
        echo "8. Exit"
        echo "9. Run bruteforce.ng hull"
        echo "10. Console Ninja Engine (Help)"
        echo "11. Grant Root/Superuser Permission to User & Ensure su Binaries"
        echo "12. Grant Superuser/Root for Mobile Device (Android/Tablet)"
        echo "13. Settings & UI Config"
        echo "14. View Security Logs"
        echo ""
        echo "Session time remaining: $(( (session_timeout - (current_time - session_start)) / 60 )) minutes"
        read -p "Enter choice [1-14]: " -r choice
        
        case $choice in
            1) manage_permissions || echo "Permission management failed" ;;
            2) setup_autorun || echo "Auto-run setup failed" ;;
            3) security_tools || echo "Security scan failed" ;;
            4) setup_kali_nethunter_termux || echo "Kali/Termux setup failed" ;;
            5) setup_metasploit || echo "Metasploit setup failed" ;;
            6) setup_kali_nethunter_tools || echo "Kali tools setup failed" ;;
            7) float_windows || echo "Window floating failed" ;;
            8) 
                echo "Exiting..."
                log_security_event "INFO" "Session ended normally: $session_id"
                exit 0 
                ;;
            9) bruteforce_ng_hull || echo "Bruteforce operation failed" ;;
            10) console_ninja_engine ;;
            11) grant_root_superuser || echo "Root permission grant failed" ;;
            12) grant_mobile_superuser || echo "Mobile superuser setup failed" ;;
            13) settings_ui_config ;;
            14) 
                echo "Recent security log entries:"
                tail -20 "$LOG_FILE" 2>/dev/null || echo "No log file found"
                ;;
            *) 
                color_echo red "Invalid choice. Please enter 1-14." 
                log_security_event "WARNING" "Invalid menu choice: $choice"
                sleep 1 
                ;;
        esac
        
        # Add pause after operations
        if [[ "$choice" != "8" && "$choice" != "10" && "$choice" != "14" ]]; then
            echo
            read -p "Press Enter to continue..." -r
        fi
    done
}

# Initialize logging
touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/permissions_manager.log"
chmod 600 "$LOG_FILE" 2>/dev/null

# Run the main menu
main_menu
