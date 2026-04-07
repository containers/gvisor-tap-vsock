# Install Go tools into tools/bin (PowerShell equivalent of tools/tools.mk)
# Usage: .\tools.ps1   or   .\tools\tools.ps1
# Requires: Go, and tools/go.mod present

$ErrorActionPreference = "Stop"

$ToolsDir = $PSScriptRoot
$ToolsBindir = [System.IO.Path]::GetFullPath((Join-Path $ToolsDir "bin"))

if (-not (Test-Path (Join-Path $ToolsDir "go.mod"))) {
    Write-Error "tools/go.mod not found. Run this script from repo root or from the tools directory."
    exit 1
}

if (-not (Test-Path $ToolsBindir)) {
    New-Item -ItemType Directory -Path $ToolsBindir -Force | Out-Null
    Write-Host "Created $ToolsBindir"
}

$env:GOBIN = $ToolsBindir
Push-Location $ToolsDir
try {
    $packages = @(
        "github.com/randall77/makefat",
        "github.com/golangci/golangci-lint/v2/cmd/golangci-lint",
        "github.com/ulikunitz/xz/cmd/gxz"
    )
    foreach ($pkg in $packages) {
        Write-Host "Installing $pkg..."
        go install $pkg
        if ($LASTEXITCODE -ne 0) {
            throw "go install $pkg failed"
        }
    }
    Write-Host "All tools installed to $ToolsBindir"
} finally {
    Pop-Location
}
