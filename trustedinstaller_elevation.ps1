# TrustedInstaller Elevation Script with Level 600 Permissions
# Enhanced Security Edition with comprehensive validation

param(
    [Parameter(Mandatory=$false)]
    [string]$TargetPath,
    
    [Parameter(Mandatory=$false)]
    [string]$Operation = "elevate",
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$Validate
)

# Security audit logging
$LogPath = "$env:TEMP\trustedinstaller_audit.log"
$SessionId = [System.Guid]::NewGuid().ToString()

function Write-SecurityLog {
    param($Level, $Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] [Session:$SessionId] [User:$env:USERNAME] $Message"
    Add-Content -Path $LogPath -Value $LogEntry -Force
    Write-Host $LogEntry -ForegroundColor $(if($Level -eq "CRITICAL"){"Red"}elseif($Level -eq "WARNING"){"Yellow"}else{"Green"})
}

# Check if running as Administrator
function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Enhanced path validation function
function Test-SecurePath {
    param([string]$Path)
    
    if ([string]::IsNullOrEmpty($Path)) {
        Write-SecurityLog "ERROR" "Empty path provided"
        return $false
    }
    
    # Block path traversal attempts
    if ($Path -match '\.\.' -or $Path -match '\.\\' -or $Path -match '\.\./') {
        Write-SecurityLog "CRITICAL" "Path traversal attempt blocked: $Path"
        return $false
    }
    
    # Block access to critical system directories
    $restrictedPaths = @(
        "$env:WINDIR\System32\config",
        "$env:WINDIR\System32\drivers",
        "$env:PROGRAMDATA\Microsoft\Crypto",
        "C:\Windows\security"
    )
    
    foreach ($restricted in $restrictedPaths) {
        if ($Path.StartsWith($restricted, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-SecurityLog "CRITICAL" "Access to restricted path blocked: $Path"
            return $false
        }
    }
    
    return $true
}

# Enhanced privilege validation
function Test-RequiredPrivileges {
    Write-SecurityLog "INFO" "Validating required privileges"
    
    try {
        # Check if TrustedInstaller service is available
        $tiService = Get-Service -Name "TrustedInstaller" -ErrorAction SilentlyContinue
        if (-not $tiService) {
            Write-SecurityLog "ERROR" "TrustedInstaller service not found"
            return $false
        }
        
        Write-SecurityLog "SUCCESS" "TrustedInstaller service validated"
        
        # Check if we can access system tools
        $systemTools = @("takeown.exe", "icacls.exe")
        foreach ($tool in $systemTools) {
            $toolPath = Get-Command $tool -ErrorAction SilentlyContinue
            if (-not $toolPath) {
                Write-SecurityLog "ERROR" "Required system tool not found: $tool"
                return $false
            }
        }
        
        Write-SecurityLog "SUCCESS" "All required system tools validated"
        return $true
    }
    catch {
        Write-SecurityLog "ERROR" "Privilege validation failed: $($_.Exception.Message)"
        return $false
    }
}

# Elevate to TrustedInstaller privileges
function Grant-TrustedInstallerPrivileges {
    Write-SecurityLog "CRITICAL" "Attempting TrustedInstaller privilege elevation for: $TargetPath"
    
    # Validate target path
    if (-not (Test-SecurePath $TargetPath)) {
        return $false
    }
    
    # Validate required privileges
    if (-not (Test-RequiredPrivileges)) {
        return $false
    }
    
    # Security confirmation unless forced
    if (-not $Force) {
        Write-Host "`n=== TRUSTEDINSTALLER LEVEL 600 ELEVATION ===" -ForegroundColor Cyan
        Write-Host "Target: $TargetPath" -ForegroundColor Yellow
        Write-Host "WARNING: This grants maximum system privileges!" -ForegroundColor Red
        Write-Host "This action will be logged and monitored.`n" -ForegroundColor Yellow
        
        $consent = Read-Host "Type 'GRANT_TRUSTEDINSTALLER' to continue"
        if ($consent -ne "GRANT_TRUSTEDINSTALLER") {
            Write-SecurityLog "INFO" "TrustedInstaller elevation cancelled by user"
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            return $false
        }
    }
    
    try {
        # Verify target exists
        if (-not (Test-Path $TargetPath)) {
            Write-SecurityLog "ERROR" "Target path does not exist: $TargetPath"
            Write-Host "Error: Target path does not exist" -ForegroundColor Red
            return $false
        }
        
        Write-SecurityLog "INFO" "Beginning TrustedInstaller ownership transfer"
        
        # Take ownership with comprehensive error handling
        Write-Host "Taking ownership..." -ForegroundColor Yellow
        $takeownArgs = @("/f", "`"$TargetPath`"", "/a")
        
        # Add recursive flag if target is directory
        if (Test-Path $TargetPath -PathType Container) {
            $takeownArgs += @("/r", "/d", "Y")
            Write-SecurityLog "INFO" "Applying recursive ownership to directory"
        }
        
        $takeownResult = & takeown.exe $takeownArgs 2>&1
        $takeownExitCode = $LASTEXITCODE
        
        if ($takeownExitCode -eq 0) {
            Write-SecurityLog "SUCCESS" "Ownership transfer completed successfully"
            Write-Host "✓ Ownership transferred" -ForegroundColor Green
        } else {
            Write-SecurityLog "ERROR" "Ownership transfer failed (Exit: $takeownExitCode): $takeownResult"
            Write-Host "✗ Ownership transfer failed" -ForegroundColor Red
            return $false
        }
        
        # Apply Level 600 permissions (maximum security)
        Write-Host "Applying Level 600 permissions..." -ForegroundColor Yellow
        Write-SecurityLog "CRITICAL" "Applying Level 600 security permissions"
        
        $icaclsArgs = @(
            "`"$TargetPath`"",
            "/inheritance:r",
            "/grant:r", "NT SERVICE\TrustedInstaller:(F)",
            "/grant:r", "$env:USERNAME:(F)",
            "/remove", "Users",
            "/remove", "Everyone",
            "/remove", "Authenticated Users"
        )
        
        # Add recursive flag for directories
        if (Test-Path $TargetPath -PathType Container) {
            $icaclsArgs += "/t"
        }
        
        $icaclsResult = & icacls.exe $icaclsArgs 2>&1
        $icaclsExitCode = $LASTEXITCODE
        
        if ($icaclsExitCode -eq 0) {
            Write-SecurityLog "SUCCESS" "Level 600 permissions applied successfully to: $TargetPath"
            Write-Host "✓ Level 600 permissions applied" -ForegroundColor Green
            Write-Host "`nTrustedInstaller Level 600 elevation completed successfully!" -ForegroundColor Green
            
            # Display final permissions
            Write-Host "`nFinal permissions:" -ForegroundColor Cyan
            & icacls.exe "`"$TargetPath`"" 2>&1 | Write-Host
            
            return $true
        } else {
            Write-SecurityLog "ERROR" "Level 600 permissions failed (Exit: $icaclsExitCode): $icaclsResult"
            Write-Host "✗ Failed to apply Level 600 permissions" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-SecurityLog "ERROR" "TrustedInstaller elevation exception: $($_.Exception.Message)"
        Write-Host "✗ TrustedInstaller elevation failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Environment validation function
function Test-Environment {
    Write-Host "=== TrustedInstaller Environment Validation ===" -ForegroundColor Cyan
    
    $issues = @()
    
    # Check admin privileges
    if (Test-AdminPrivileges) {
        Write-Host "✓ Administrator privileges verified" -ForegroundColor Green
    } else {
        Write-Host "✗ Not running as Administrator" -ForegroundColor Red
        $issues += "Administrator privileges required"
    }
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion.Major
    if ($psVersion -ge 5) {
        Write-Host "✓ PowerShell version $psVersion supported" -ForegroundColor Green
    } else {
        Write-Host "✗ PowerShell version $psVersion not optimal" -ForegroundColor Yellow
        $issues += "PowerShell 5.0+ recommended"
    }
    
    # Check system tools
    $tools = @("takeown.exe", "icacls.exe")
    foreach ($tool in $tools) {
        if (Get-Command $tool -ErrorAction SilentlyContinue) {
            Write-Host "✓ $tool available" -ForegroundColor Green
        } else {
            Write-Host "✗ $tool not found" -ForegroundColor Red
            $issues += "$tool missing"
        }
    }
    
    # Check TrustedInstaller service
    $tiService = Get-Service -Name "TrustedInstaller" -ErrorAction SilentlyContinue
    if ($tiService) {
        Write-Host "✓ TrustedInstaller service available (Status: $($tiService.Status))" -ForegroundColor Green
    } else {
        Write-Host "✗ TrustedInstaller service not found" -ForegroundColor Red
        $issues += "TrustedInstaller service unavailable"
    }
    
    # Check log path
    if (Test-Path (Split-Path $LogPath -Parent)) {
        Write-Host "✓ Logging directory accessible" -ForegroundColor Green
    } else {
        Write-Host "! Logging directory not optimal" -ForegroundColor Yellow
    }
    
    Write-Host "`n=== Validation Summary ===" -ForegroundColor Cyan
    if ($issues.Count -eq 0) {
        Write-Host "✓ Environment ready for TrustedInstaller Level 600 operations" -ForegroundColor Green
    } else {
        Write-Host "! Issues found:" -ForegroundColor Yellow
        foreach ($issue in $issues) {
            Write-Host "  - $issue" -ForegroundColor Yellow
        }
    }
    
    return ($issues.Count -eq 0)
}

# Main execution
Write-SecurityLog "INFO" "TrustedInstaller elevation script started (Operation: $Operation)"

# Handle validation mode
if ($Validate) {
    $validationResult = Test-Environment
    exit $(if ($validationResult) { 0 } else { 1 })
}

# Require admin privileges for all operations
if (-not (Test-AdminPrivileges)) {
    Write-SecurityLog "ERROR" "Script must be run as Administrator"
    Write-Host "Error: Must run PowerShell as Administrator" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

switch ($Operation.ToLower()) {
    "elevate" {
        if ([string]::IsNullOrEmpty($TargetPath)) {
            Write-Host "Error: TargetPath required for elevation operation" -ForegroundColor Red
            Write-Host "Usage: -TargetPath 'C:\path\to\file' -Operation elevate" -ForegroundColor Yellow
            exit 1
        }
        
        $success = Grant-TrustedInstallerPrivileges
        exit $(if ($success) { 0 } else { 1 })
    }
    "audit" {
        Write-Host "=== TrustedInstaller Security Audit Log ===" -ForegroundColor Cyan
        if (Test-Path $LogPath) {
            Write-Host "Log file: $LogPath`n" -ForegroundColor Yellow
            Get-Content $LogPath | Select-Object -Last 25 | ForEach-Object {
                if ($_ -match "CRITICAL") {
                    Write-Host $_ -ForegroundColor Red
                } elseif ($_ -match "WARNING") {
                    Write-Host $_ -ForegroundColor Yellow
                } elseif ($_ -match "SUCCESS") {
                    Write-Host $_ -ForegroundColor Green
                } else {
                    Write-Host $_
                }
            }
        } else {
            Write-Host "No audit log found at: $LogPath" -ForegroundColor Yellow
        }
        exit 0
    }
    "validate" {
        $validationResult = Test-Environment
        exit $(if ($validationResult) { 0 } else { 1 })
    }
    default {
        Write-Host "Invalid operation: $Operation" -ForegroundColor Red
        Write-Host "Valid operations: elevate, audit, validate" -ForegroundColor Yellow
        Write-Host "`nExamples:" -ForegroundColor Cyan
        Write-Host "  .\trustedinstaller_elevation.ps1 -TargetPath 'C:\file.txt' -Operation elevate"
        Write-Host "  .\trustedinstaller_elevation.ps1 -Operation audit"
        Write-Host "  .\trustedinstaller_elevation.ps1 -Operation validate"
        exit 1
    }
}
