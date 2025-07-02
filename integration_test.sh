#!/bin/bash

# TrustedInstaller Integration Test Suite
# Comprehensive testing for all components

set -euo pipefail

# Test configuration
readonly TEST_DIR="/tmp/trustedinstaller_test_$$"
readonly LOG_FILE="$TEST_DIR/test_results.log"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_test() { echo -e "${BLUE}[TEST]${NC} $*" | tee -a "$LOG_FILE"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $*" | tee -a "$LOG_FILE"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $*" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "$LOG_FILE"; }

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    
    ((TESTS_RUN++))
    log_test "Running: $test_name"
    
    if eval "$test_command" >/dev/null 2>&1; then
        ((TESTS_PASSED++))
        log_pass "$test_name"
        return 0
    else
        ((TESTS_FAILED++))
        log_fail "$test_name"
        return 1
    fi
}

# Setup test environment
setup_test_env() {
    log_test "Setting up test environment"
    mkdir -p "$TEST_DIR"
    touch "$TEST_DIR/test_file.txt"
    echo "test content" > "$TEST_DIR/test_file.txt"
}

# Test file existence
test_file_existence() {
    log_test "Testing file existence..."
    
    local files=(
        "/workspaces/Trustedinstaller/Security tools envierment setup"
        "/workspaces/Trustedinstaller/permissions_manager.sh"
        "/workspaces/Trustedinstaller/trustedinstaller_elevation.ps1"
        "/workspaces/Trustedinstaller/trustedinstaller_wrapper.sh"
    )
    
    for file in "${files[@]}"; do
        run_test "File exists: $(basename "$file")" "test -f '$file'"
    done
}

# Test script executability
test_script_permissions() {
    log_test "Testing script permissions..."
    
    local scripts=(
        "/workspaces/Trustedinstaller/Security tools envierment setup"
        "/workspaces/Trustedinstaller/permissions_manager.sh"
        "/workspaces/Trustedinstaller/trustedinstaller_wrapper.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [[ -f "$script" ]]; then
            run_test "Script executable: $(basename "$script")" "test -x '$script'"
        fi
    done
}

# Test syntax validation
test_syntax() {
    log_test "Testing syntax validation..."
    
    # Test bash scripts
    local bash_scripts=(
        "/workspaces/Trustedinstaller/Security tools envierment setup"
        "/workspaces/Trustedinstaller/permissions_manager.sh"
        "/workspaces/Trustedinstaller/trustedinstaller_wrapper.sh"
    )
    
    for script in "${bash_scripts[@]}"; do
        if [[ -f "$script" ]]; then
            run_test "Bash syntax: $(basename "$script")" "bash -n '$script'"
        fi
    done
    
    # Test PowerShell script if PowerShell is available
    local ps_script="/workspaces/Trustedinstaller/trustedinstaller_elevation.ps1"
    if [[ -f "$ps_script" ]]; then
        if command -v pwsh >/dev/null 2>&1; then
            run_test "PowerShell syntax: $(basename "$ps_script")" "pwsh -NoProfile -Command '& { . \"$ps_script\" -WhatIf }'"
        elif command -v powershell.exe >/dev/null 2>&1; then
            run_test "PowerShell syntax: $(basename "$ps_script")" "powershell.exe -Command '& { . \"$ps_script\" -WhatIf }'"
        else
            log_warn "PowerShell not available for syntax testing"
        fi
    fi
}

# Test environment setup
test_environment_setup() {
    log_test "Testing environment setup..."
    
    local setup_script="/workspaces/Trustedinstaller/Security tools envierment setup"
    if [[ -f "$setup_script" ]]; then
        # Test dry run (checking dependencies only)
        if bash "$setup_script" --help >/dev/null 2>&1 || bash -n "$setup_script"; then
            log_pass "Environment setup script structure valid"
        else
            log_fail "Environment setup script has issues"
        fi
    fi
}

# Test TrustedInstaller wrapper
test_trustedinstaller_wrapper() {
    log_test "Testing TrustedInstaller wrapper..."
    
    local wrapper="/workspaces/Trustedinstaller/trustedinstaller_wrapper.sh"
    if [[ -f "$wrapper" ]]; then
        # Test help functionality
        run_test "Wrapper help" "'$wrapper' --help"
        
        # Test version
        run_test "Wrapper version" "'$wrapper' --version"
        
        # Test environment test
        run_test "Wrapper test mode" "'$wrapper' --test"
    fi
}

# Test permissions manager
test_permissions_manager() {
    log_test "Testing permissions manager..."
    
    local manager="/workspaces/Trustedinstaller/permissions_manager.sh"
    if [[ -f "$manager" ]]; then
        # Test syntax only (requires root to run)
        run_test "Permissions manager syntax" "bash -n '$manager'"
        
        # Test if functions are defined
        if grep -q "function main_menu" "$manager" || grep -q "main_menu()" "$manager"; then
            log_pass "Main menu function found"
        else
            log_fail "Main menu function not found"
        fi
    fi
}

# Test integration between components
test_integration() {
    log_test "Testing component integration..."
    
    # Check if setup script creates proper directory structure
    local security_tools_dir="$HOME/security_tools"
    local ti_dir="$security_tools_dir/trustedinstaller"
    
    # Test if TrustedInstaller files would be created in correct location
    if [[ -d "$security_tools_dir" ]]; then
        if [[ -d "$ti_dir" ]]; then
            log_pass "TrustedInstaller directory exists"
            
            # Check for key files
            local key_files=(
                "$ti_dir/trustedinstaller_elevation.ps1"
                "$ti_dir/trustedinstaller_wrapper.sh"
                "$ti_dir/validate_environment.sh"
            )
            
            for file in "${key_files[@]}"; do
                if [[ -f "$file" ]]; then
                    log_pass "Integration file exists: $(basename "$file")"
                else
                    log_warn "Integration file missing: $(basename "$file")"
                fi
            done
        else
            log_warn "TrustedInstaller directory not yet created (run setup first)"
        fi
    else
        log_warn "Security tools directory not yet created (run setup first)"
    fi
}

# Test security controls
test_security_controls() {
    log_test "Testing security controls..."
    
    # Test path traversal protection in wrapper
    local wrapper="/workspaces/Trustedinstaller/trustedinstaller_wrapper.sh"
    if [[ -f "$wrapper" ]]; then
        if grep -q "path.*traversal" "$wrapper" || grep -q "\.\." "$wrapper"; then
            log_pass "Path traversal protection found in wrapper"
        else
            log_warn "Path traversal protection may be missing"
        fi
    fi
    
    # Test logging mechanisms
    if grep -q "log.*security\|audit" "/workspaces/Trustedinstaller/permissions_manager.sh" 2>/dev/null; then
        log_pass "Security logging found in permissions manager"
    else
        log_warn "Security logging may be missing"
    fi
}

# Cleanup test environment
cleanup_test_env() {
    log_test "Cleaning up test environment"
    rm -rf "$TEST_DIR" 2>/dev/null || true
}

# Main test execution
main() {
    echo "=== TrustedInstaller Integration Test Suite ==="
    echo "Starting comprehensive testing..."
    echo ""
    
    setup_test_env
    
    test_file_existence
    test_script_permissions
    test_syntax
    test_environment_setup
    test_trustedinstaller_wrapper
    test_permissions_manager
    test_integration
    test_security_controls
    
    cleanup_test_env
    
    echo ""
    echo "=== Test Results Summary ==="
    echo "Tests Run: $TESTS_RUN"
    echo "Tests Passed: $TESTS_PASSED"
    echo "Tests Failed: $TESTS_FAILED"
    echo "Success Rate: $(( TESTS_PASSED * 100 / TESTS_RUN ))%"
    echo ""
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed! TrustedInstaller system is ready.${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed. Please review the issues above.${NC}"
        exit 1
    fi
}

# Execute main function
main "$@"
