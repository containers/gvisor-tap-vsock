# PowerShell build script for Windows-specific binaries
# This script builds win-sshproxy, gvproxy for Windows (amd64 and arm64), and gvforwarder for Linux
# Usage: .\winmake [target]
# Targets: clean, win-sshproxy, gvproxy, gvforwarder, test-win
# Default: builds all (win-sshproxy, gvproxy, gvforwarder)

param(
    [string]$Target = "all"
)

$ErrorActionPreference = "Stop"

# Get git version (equivalent to: git describe --always --dirty)
function Get-GitVersion {
    try {
        $version = git describe --always --dirty 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to get git version, using 'unknown'"
            return "unknown"
        }
        return $version.Trim()
    } catch {
        Write-Warning "Failed to get git version, using 'unknown'"
        return "unknown"
    }
}

# Create bin directory if it doesn't exist
function Ensure-BinDirectory {
    if (-not (Test-Path "bin")) {
        New-Item -ItemType Directory -Path "bin" | Out-Null
        Write-Host "Created bin directory"
    }
}

# Clean bin directory
function Clean-BinDirectory {
    if (Test-Path "bin") {
        Remove-Item -Path "bin" -Recurse -Force
        Write-Host "Cleaned bin directory"
    }
}

# Ensure Go tools (golangci-lint, makefat, etc.) are installed in tools/bin
function Ensure-ToolsInstalled {
    $toolsScript = Join-Path $PSScriptRoot "tools\tools.ps1"
    if (-not (Test-Path $toolsScript)) {
        Write-Error "tools\tools.ps1 not found at $toolsScript"
        exit 1
    }
    & $toolsScript
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install tools"
    }
}

# Build Windows binary
function Build-WindowsBinary {
    param(
        [string]$Arch,
        [string]$OutputPath,
        [string]$SourcePath,
        [string]$GitVersion
    )
    
    $ldflags = "-s -w -X github.com/containers/gvisor-tap-vsock/pkg/types.gitVersion=$GitVersion -H=windowsgui"
    
    Write-Host "Building $OutputPath for $Arch..."
    
    # Set environment variables for this build
    $originalGOOS = $env:GOOS
    $originalGOARCH = $env:GOARCH
    
    try {
        $env:GOOS = "windows"
        $env:GOARCH = $Arch
        
        go build -ldflags $ldflags -o $OutputPath $SourcePath
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build $OutputPath"
        }
        
        Write-Host "Successfully built $OutputPath"
    } finally {
        # Restore original environment variables
        if ($originalGOOS) {
            $env:GOOS = $originalGOOS
        } else {
            Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
        }
        if ($originalGOARCH) {
            $env:GOARCH = $originalGOARCH
        } else {
            Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
        }
    }
}

# Build win-sshproxy target
function Build-WinSshProxy {
    param([string]$GitVersion)
    
    Write-Host "Building win-sshproxy..."
    Build-WindowsBinary -Arch "amd64" -OutputPath "bin\win-sshproxy.exe" -SourcePath "./cmd/win-sshproxy" -GitVersion $GitVersion
    Build-WindowsBinary -Arch "arm64" -OutputPath "bin\win-sshproxy-arm64.exe" -SourcePath "./cmd/win-sshproxy" -GitVersion $GitVersion
    Write-Host ""
}

# Build gvproxy target
function Build-WinGvProxy {
    param([string]$GitVersion)
    
    Write-Host "Building gvproxy..."
    Build-WindowsBinary -Arch "amd64" -OutputPath "bin\gvproxy.exe" -SourcePath "./cmd/gvproxy" -GitVersion $GitVersion
    Build-WindowsBinary -Arch "arm64" -OutputPath "bin\gvproxy-arm64.exe" -SourcePath "./cmd/gvproxy" -GitVersion $GitVersion
    Write-Host ""
}

# Build gvforwarder for Linux (used inside the VM; cross-compile from Windows)
function Build-GvForwarder {
    param([string]$GitVersion)
    
    $ldflags = "-s -w -X github.com/containers/gvisor-tap-vsock/pkg/types.gitVersion=$GitVersion"
    
    Write-Host "Building gvforwarder for Linux..."
    
    $originalGOOS = $env:GOOS
    $originalCGO = $env:CGO_ENABLED
    
    try {
        $env:GOOS = "linux"
        $env:CGO_ENABLED = "0"
        
        go build -ldflags $ldflags -o "bin\gvforwarder" "./cmd/vm"
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build gvforwarder"
        }
        
        Write-Host "Successfully built bin\gvforwarder (Linux)"
    } finally {
        if ($originalGOOS) {
            $env:GOOS = $originalGOOS
        } else {
            Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
        }
        if ($null -ne $originalCGO) {
            $env:CGO_ENABLED = $originalCGO
        } else {
            Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue
        }
    }
    Write-Host ""
}

# Main execution
try {
    Write-Host "Windows Build Script for gvisor-tap-vsock"
    Write-Host "=========================================="
    Write-Host ""
    
    # Ensure tools are installed (skip for clean)
    if ($Target.ToLower() -ne "clean") {
        Ensure-ToolsInstalled
        Write-Host ""
    }
    
    # Handle targets
    switch ($Target.ToLower()) {
        "clean" {
            Clean-BinDirectory
            Write-Host "Clean completed successfully!"
            exit 0
        }
        "win-sshproxy" {
            Ensure-BinDirectory
            $gitVersion = Get-GitVersion
            Write-Host "Git version: $gitVersion"
            Write-Host ""
            Build-WinSshProxy -GitVersion $gitVersion
            Write-Host "=========================================="
            Write-Host "Build completed successfully!"
            Write-Host ""
            Write-Host "Built binaries:"
            Write-Host "  - bin\win-sshproxy.exe (amd64)"
            Write-Host "  - bin\win-sshproxy-arm64.exe (arm64)"
            exit 0
        }
        "gvproxy" {
            Ensure-BinDirectory
            $gitVersion = Get-GitVersion
            Write-Host "Git version: $gitVersion"
            Write-Host ""
            Build-WinGvProxy -GitVersion $gitVersion
            Write-Host "=========================================="
            Write-Host "Build completed successfully!"
            Write-Host ""
            Write-Host "Built binaries:"
            Write-Host "  - bin\gvproxy.exe (amd64)"
            Write-Host "  - bin\gvproxy-arm64.exe (arm64)"
            exit 0
        }
        "gvforwarder" {
            Ensure-BinDirectory
            $gitVersion = Get-GitVersion
            Write-Host "Git version: $gitVersion"
            Write-Host ""
            Build-GvForwarder -GitVersion $gitVersion
            Write-Host "=========================================="
            Write-Host "Build completed successfully!"
            Write-Host ""
            Write-Host "Built binary:"
            Write-Host "  - bin\gvforwarder (Linux)"
            exit 0
        }
        "test-win" {
            # Build gvproxy and gvforwarder (required for tests)
            Ensure-BinDirectory
            $gitVersion = Get-GitVersion
            Write-Host "Git version: $gitVersion"
            Write-Host ""
            Write-Host "Building gvproxy for tests..."
            Build-WinGvProxy -GitVersion $gitVersion
            Write-Host "Building gvforwarder for tests..."
            Build-GvForwarder -GitVersion $gitVersion
            Write-Host "Running Windows tests..."
            Write-Host "=========================================="
            go test -timeout 20m -v ./test-win
            if ($LASTEXITCODE -ne 0) {
                throw "Tests failed with exit code $LASTEXITCODE"
            }
            Write-Host "=========================================="
            Write-Host "Tests completed successfully!"
            exit 0
        }
        "all" {
            Ensure-BinDirectory
            $gitVersion = Get-GitVersion
            Write-Host "Git version: $gitVersion"
            Write-Host ""
            Build-WinSshProxy -GitVersion $gitVersion
            Build-WinGvProxy -GitVersion $gitVersion
            Build-GvForwarder -GitVersion $gitVersion
            Write-Host "=========================================="
            Write-Host "Build completed successfully!"
            Write-Host ""
            Write-Host "Built binaries:"
            Write-Host "  - bin\win-sshproxy.exe (amd64)"
            Write-Host "  - bin\win-sshproxy-arm64.exe (arm64)"
            Write-Host "  - bin\gvproxy.exe (amd64)"
            Write-Host "  - bin\gvproxy-arm64.exe (arm64)"
            Write-Host "  - bin\gvforwarder (Linux)"
            exit 0
        }
        default {
            Write-Host "Unknown target: $Target"
            Write-Host ""
            Write-Host "Available targets:"
            Write-Host "  clean         - Remove bin directory"
            Write-Host "  win-sshproxy  - Build win-sshproxy binaries"
            Write-Host "  gvproxy       - Build gvproxy binaries"
            Write-Host "  gvforwarder   - Build gvforwarder for Linux"
            Write-Host "  test-win      - Build gvproxy and gvforwarder, then run Windows tests"
            Write-Host "  all           - Build all binaries (default)"
            exit 1
        }
    }
    
} catch {
    Write-Host ""
    Write-Host "=========================================="
    Write-Host "Build failed with error:"
    Write-Host $_.Exception.Message
    exit 1
}
