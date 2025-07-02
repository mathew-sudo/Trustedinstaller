#!/bin/bash

# TrustedInstaller Cross-Platform Wrapper
# Enhanced version integrated with Security Tools Environment

set -euo pipefail
IFS=$'\n\t'

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="${SCRIPT_DIR}/trustedinstaller_operations.log"
readonly SECURITY_TOOLS_HOME="${SECURITY_TOOLS_HOME:-$HOME/security_tools}"

# Enhanced security logging with audit trail
log_operation() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local user_info="USER:$(whoami) PID:$$"
    
    local log_entry="[$timestamp] [$level] [$user_info] $message"
    echo "$log_entry" | tee -a "$LOG_FILE"
    
    # Also log to system log for security monitoring
    logger -t "trustedinstaller" -p auth.info "[$level] $message" 2>/dev/null || true
}

# Enhanced OS detection with better validation
detect_os() {
    if [[ -n "${WINDIR:-}" ]] || [[ -n "${PROGRAMFILES:-}" ]] || command -v powershell.exe >/dev/null 2>&1; then
        echo "windows"
    elif [[ "$(uname)" == "Darwin" ]]; then
        echo "macos"
    elif [[ "$(uname)" == "Linux" ]]; then
        echo "linux"
    else
        echo "unknown"
    fi
}

# Enhanced path validation with security checks
validate_target_path() {
    local target_path="$1"
    
    # Check for empty path
    if [[ -z "$target_path" ]]; then
        log_operation "ERROR" "Empty target path provided"
        echo "Error: Target path cannot be empty"
        return 1
    fi
    
    # Prevent path traversal attacks
    if [[ "$target_path" =~ \.\./|\.\.\\ ]]; then
        log_operation "CRITICAL" "Path traversal attempt blocked: $target_path"
        echo "Error: Path traversal not allowed"
        return 1
    fi
    
    # Block access to critical system files
    local restricted_paths=("/etc/shadow" "/etc/passwd" "/root/.ssh" "/proc" "/sys/kernel" "/boot")
    for restricted in "${restricted_paths[@]}"; do
        if [[ "$target_path" == "$restricted"* ]]; then
            log_operation "CRITICAL" "Attempt to access restricted path: $target_path"
            echo "Error: Access to system critical files is restricted"
            return 1
        fi
    done
    
    return 0
}

# Windows TrustedInstaller elevation with enhanced error handling
elevate_windows() {
    local target_path="$1"
    log_operation "CRITICAL" "Windows TrustedInstaller elevation: $target_path"
    
    # Check for PowerShell availability and version
    local ps_cmd=""
    local ps_version=""
    
    if command -v powershell.exe >/dev/null 2>&1; then
        ps_cmd="powershell.exe"
        ps_version=$(powershell.exe -Command '$PSVersionTable.PSVersion.Major' 2>/dev/null || echo "unknown")
    elif command -v pwsh >/dev/null 2>&1; then
        ps_cmd="pwsh"
        ps_version=$(pwsh -Command '$PSVersionTable.PSVersion.Major' 2>/dev/null || echo "unknown")
    else
        echo "Error: PowerShell not available"
        log_operation "ERROR" "PowerShell not found on Windows system"
        return 1
    fi
    
    log_operation "INFO" "Using $ps_cmd (version: $ps_version)"
    
    # Locate PowerShell elevation script
    local script_path=""
    local possible_locations=(
        "$SECURITY_TOOLS_HOME/trustedinstaller/trustedinstaller_elevation.ps1"
        "$SCRIPT_DIR/trustedinstaller_elevation.ps1"
        "$(dirname "$SCRIPT_DIR")/trustedinstaller/trustedinstaller_elevation.ps1"
    )
    
    for location in "${possible_locations[@]}"; do
        if [[ -f "$location" ]]; then
            script_path="$location"
            break
        fi
    done
    
    if [[ -z "$script_path" ]]; then
        echo "Error: TrustedInstaller PowerShell script not found"
        log_operation "ERROR" "PowerShell elevation script not found in any expected location"
        echo "Expected locations:"
        printf '  %s\n' "${possible_locations[@]}"
        return 1
    fi
    
    log_operation "INFO" "Using PowerShell script: $script_path"
    
    # Execute elevation script with timeout
    if timeout 300 "$ps_cmd" -ExecutionPolicy Bypass -File "$script_path" -TargetPath "$target_path" -Operation "elevate"; then
        log_operation "SUCCESS" "Windows TrustedInstaller elevation completed"
        return 0
    else
        log_operation "ERROR" "Windows TrustedInstaller elevation failed"
        return 1
    fi
}

# Unix/Linux Level 600 elevation with enhanced validation
elevate_unix() {
    local target_path="$1"
    log_operation "CRITICAL" "Unix Level 600 elevation: $target_path"
    
    # Resolve path to prevent symlink attacks
    local resolved_path
    resolved_path=$(realpath "$target_path" 2>/dev/null) || {
        echo "Error: Cannot resolve path: $target_path"
        log_operation "ERROR" "Path resolution failed: $target_path"
        return 1
    }
    
    # Validate path exists
    if [[ ! -e "$resolved_path" ]]; then
        echo "Error: Path does not exist: $resolved_path"
        log_operation "ERROR" "Target path does not exist: $resolved_path"
        return 1
    fi
    
    # Check if we have sufficient privileges
    if [[ $EUID -ne 0 ]]; then
        echo "Warning: Not running as root. Attempting with current privileges..."
        log_operation "WARNING" "Level 600 elevation attempted without root privileges"
    fi
    
    # Apply maximum restrictive permissions (600)
    local chmod_result=0
    local chown_result=0
    
    chmod 600 "$resolved_path" || chmod_result=$?
    
    if [[ $EUID -eq 0 ]]; then
        chown root:root "$resolved_path" 2>/dev/null || chown_result=$?
    fi
    
    if [[ $chmod_result -eq 0 ]]; then
        log_operation "SUCCESS" "Level 600 permissions applied to: $resolved_path"
        echo "Permissions applied: $(ls -la "$resolved_path")"
        
        if [[ $chown_result -ne 0 && $EUID -eq 0 ]]; then
            log_operation "WARNING" "Ownership change failed but permissions applied"
            echo "Warning: Could not change ownership to root:root"
        fi
        
        return 0
    else
        log_operation "ERROR" "Failed to apply Level 600 permissions: $resolved_path"
        echo "Error: Failed to change permissions (chmod exit code: $chmod_result)"
        return 1
    fi
}

# macOS equivalent elevation with Homebrew compatibility
elevate_macos() {
    local target_path="$1"
    log_operation "CRITICAL" "macOS Level 600 elevation: $target_path"
    
    # Resolve path
    local resolved_path
    resolved_path=$(realpath "$target_path" 2>/dev/null) || {
        echo "Error: Cannot resolve path: $target_path"
        log_operation "ERROR" "Path resolution failed: $target_path"
        return 1
    }
    
    # Validate path exists
    if [[ ! -e "$resolved_path" ]]; then
        echo "Error: Path does not exist: $resolved_path"
        log_operation "ERROR" "Target path does not exist: $resolved_path"
        return 1
    fi
    
    # Apply permissions
    if chmod 600 "$resolved_path"; then
        # Try to change ownership (may require sudo)
        if [[ $EUID -eq 0 ]]; then
            chown root:wheel "$resolved_path" 2>/dev/null || {
                log_operation "WARNING" "Could not change ownership to root:wheel"
                echo "Warning: Could not change ownership (continuing with current owner)"
            }
        elif command -v sudo >/dev/null 2>&1; then
            if sudo chown root:wheel "$resolved_path" 2>/dev/null; then
                log_operation "INFO" "Ownership changed to root:wheel via sudo"
            else
                log_operation "WARNING" "Sudo ownership change failed"
                echo "Warning: Could not change ownership with sudo"
            fi
        fi
        
        log_operation "SUCCESS" "macOS Level 600 permissions applied: $resolved_path"
        echo "Permissions applied: $(ls -la "$resolved_path")"
        return 0
    else
        log_operation "ERROR" "Failed to apply macOS Level 600 permissions: $resolved_path"
        echo "Error: Failed to change permissions"
        return 1
    fi
}

# Main elevation function with comprehensive error handling
elevate_to_level_600() {
    local target_path="$1"
    local os_type
    os_type=$(detect_os)
    
    # Validate target path before proceeding
    if ! validate_target_path "$target_path"; then
        return 1
    fi
    
    echo "=== TrustedInstaller Level 600 Elevation ==="
    echo "Target: $target_path"
    echo "Platform: $os_type"
    echo "Script Directory: $SCRIPT_DIR"
    echo ""
    
    # Security confirmation with timeout
    echo "WARNING: This will apply maximum security permissions (Level 600)"
    echo "This grants exclusive access to the system administrator only."
    echo "Operation will be logged for security audit."
    echo ""
    
    read -t 30 -p "Continue? (y/N): " -r confirm || {
        echo ""
        echo "Operation timed out or interrupted."
        log_operation "INFO" "Level 600 elevation cancelled (timeout/interrupt)"
        return 1
    }
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Operation cancelled by user."
        log_operation "INFO" "Level 600 elevation cancelled by user"
        return 0
    fi
    
    log_operation "INFO" "Level 600 elevation approved for: $target_path (OS: $os_type)"
    
    case "$os_type" in
        "windows")
            elevate_windows "$target_path"
            ;;
        "linux")
            elevate_unix "$target_path"
            ;;
        "macos")
            elevate_macos "$target_path"
            ;;
        "unknown")
            echo "Error: Unsupported or unknown operating system"
            log_operation "ERROR" "Unsupported OS detected: $(uname -a)"
            return 1
            ;;
        *)
            echo "Error: Unsupported operating system: $os_type"
            log_operation "ERROR" "Unsupported OS: $os_type"
            return 1
            ;;
    esac
}

# Enhanced command line interface with help system
show_help() {
    cat << 'EOF'
TrustedInstaller Level 600 Elevation Tool

USAGE:
    trustedinstaller_wrapper.sh [OPTIONS] <target_path>
    trustedinstaller_wrapper.sh [OPTIONS]

DESCRIPTION:
    Applies maximum security permissions (Level 600) to files and directories.
    Cross-platform compatible with Windows, Linux, and macOS.

OPTIONS:
    -h, --help      Show this help message
    -v, --version   Show version information
    -t, --test      Test environment without making changes

EXAMPLES:
    trustedinstaller_wrapper.sh /path/to/secure/file
    trustedinstaller_wrapper.sh C:\Important\Document.txt
    trustedinstaller_wrapper.sh --test

SECURITY:
    - All operations are logged for audit purposes
    - Requires elevated privileges for optimal functionality
    - Path traversal and critical system file access blocked
    - Confirmation required before applying changes

EOF
}

# Version information
show_version() {
    echo "TrustedInstaller Level 600 Elevation Tool v2.1"
    echo "Enhanced Security Edition"
    echo "Compatible with: Windows, Linux, macOS"
}

# Test environment function
test_environment() {
    echo "=== Environment Test Mode ==="
    
    local os_type
    os_type=$(detect_os)
    echo "Detected OS: $os_type"
    
    echo "Script Directory: $SCRIPT_DIR"
    echo "Log File: $LOG_FILE"
    echo "Security Tools Home: $SECURITY_TOOLS_HOME"
    
    # Check for required tools
    echo ""
    echo "Tool Availability:"
    
    case "$os_type" in
        "windows")
            if command -v powershell.exe >/dev/null 2>&1; then
                echo "✓ PowerShell.exe available"
            elif command -v pwsh >/dev/null 2>&1; then
                echo "✓ PowerShell Core available"
            else
                echo "✗ No PowerShell found"
            fi
            ;;
        "linux"|"macos")
            echo "✓ Unix-compatible system"
            if [[ $EUID -eq 0 ]]; then
                echo "✓ Running with root privileges"
            else
                echo "! Running without root privileges (may limit functionality)"
            fi
            ;;
    esac
    
    # Test logging
    log_operation "TEST" "Environment validation completed"
    echo ""
    echo "✓ Logging system functional"
    echo "✓ Environment test completed successfully"
}

# Enhanced command line interface
main() {
    local target_path=""
    local show_help_flag=false
    local show_version_flag=false
    local test_mode=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help_flag=true
                shift
                ;;
            -v|--version)
                show_version_flag=true
                shift
                ;;
            -t|--test)
                test_mode=true
                shift
                ;;
            -*)
                echo "Error: Unknown option $1"
                echo "Use --help for usage information"
                exit 1
                ;;
            *)
                if [[ -z "$target_path" ]]; then
                    target_path="$1"
                else
                    echo "Error: Multiple target paths specified"
                    echo "Use --help for usage information"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Handle flags
    if [[ "$show_help_flag" == true ]]; then
        show_help
        exit 0
    fi
    
    if [[ "$show_version_flag" == true ]]; then
        show_version
        exit 0
    fi
    
    if [[ "$test_mode" == true ]]; then
        test_environment
        exit 0
    fi
    
    # Interactive mode if no target path provided
    if [[ -z "$target_path" ]]; then
        echo "=== TrustedInstaller Level 600 Elevation ==="
        echo "Cross-platform privilege escalation tool"
        echo ""
        echo "Enter target path for Level 600 elevation:"
        read -r target_path
    fi
    
    # Validate target path
    if [[ -z "$target_path" ]]; then
        echo "Error: Target path cannot be empty"
        echo "Use --help for usage information"
        exit 1
    fi
    
    # Execute elevation
    elevate_to_level_600 "$target_path"
}

# Initialize logging directory
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/trustedinstaller_operations.log"

# Handle interrupts gracefully
trap 'echo ""; log_operation "WARNING" "Operation interrupted by user"; exit 130' INT TERM

# Execute main function
main "$@"
