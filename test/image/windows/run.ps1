param(
    [string]$TargetFolder = "gvisor-e2e"
)

$ErrorActionPreference = "Stop"

$root = Join-Path $HOME $TargetFolder
$binDir = Join-Path $root "bin"
$tmpDir = Join-Path $root "tmp"
$resultsDir = Join-Path $root "results"

New-Item -ItemType Directory -Force -Path $tmpDir, $resultsDir | Out-Null

function New-JUnitReport {
    param(
        [string]$Path,
        [string]$SuiteName,
        [object[]]$Cases,
        [string]$ErrorMessage
    )

    $failures = @($Cases | Where-Object { $_.Status -eq "failure" }).Count
    $skipped = @($Cases | Where-Object { $_.Status -eq "skipped" }).Count
    $suiteName = [System.Security.SecurityElement]::Escape($SuiteName)

    $xml = [System.Text.StringBuilder]::new()
    [void]$xml.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
    [void]$xml.AppendLine("<testsuites>")
    [void]$xml.AppendLine("  <testsuite name=`"$suiteName`" tests=`"$($Cases.Count)`" failures=`"$failures`" errors=`"0`" skipped=`"$skipped`">")

    foreach ($case in $Cases) {
        $caseName = [System.Security.SecurityElement]::Escape([string]$case.Name)
        [void]$xml.AppendLine("    <testcase classname=`"$suiteName`" name=`"$caseName`">")
        if ($case.Status -eq "failure") {
            $message = [System.Security.SecurityElement]::Escape([string]$case.Message)
            [void]$xml.AppendLine("      <failure message=`"$message`"></failure>")
        } elseif ($case.Status -eq "skipped") {
            [void]$xml.AppendLine("      <skipped></skipped>")
        }
        [void]$xml.AppendLine("    </testcase>")
    }

    if ($ErrorMessage) {
        $message = [System.Security.SecurityElement]::Escape($ErrorMessage)
        [void]$xml.AppendLine("    <system-err>$message</system-err>")
    }

    [void]$xml.AppendLine("  </testsuite>")
    [void]$xml.AppendLine("</testsuites>")
    [System.IO.File]::WriteAllText($Path, $xml.ToString(), [System.Text.UTF8Encoding]::new($false))
}

function Invoke-GinkgoTest {
    param(
        [string]$Name,
        [string]$Executable,
        [string[]]$Arguments
    )

    if (-not (Test-Path $Executable)) {
        throw "Missing test binary: $Executable"
    }

    $log = Join-Path $resultsDir "$Name.log"
    $junit = Join-Path $resultsDir "$Name.xml"
    $allArguments = @($Arguments) + @("--ginkgo.junit-report=$junit")

    $output = @(& $Executable @allArguments *>&1 | ForEach-Object { $_.ToString() } | Tee-Object -FilePath $log)
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        throw "$Name failed with exit code $exitCode"
    }
    if (-not (Test-Path $junit)) {
        throw "$Name did not generate a JUnit report"
    }
}

function Invoke-GoTest {
    param(
        [string]$Name,
        [string]$Executable,
        [string[]]$Arguments
    )

    if (-not (Test-Path $Executable)) {
        throw "Missing test binary: $Executable"
    }

    $log = Join-Path $resultsDir "$Name.log"
    $junit = Join-Path $resultsDir "$Name.xml"
    $output = @(& $Executable -test.v @Arguments *>&1 | ForEach-Object { $_.ToString() } | Tee-Object -FilePath $log)
    $exitCode = $LASTEXITCODE
    $cases = @()

    foreach ($line in $output) {
        if ($line -match '^\s*--- (PASS|FAIL|SKIP): (?<name>\S+)') {
            $status = switch ($Matches[1]) {
                "PASS" { "pass" }
                "FAIL" { "failure" }
                "SKIP" { "skipped" }
            }
            $cases += [PSCustomObject]@{
                Name    = $Matches["name"]
                Status  = $status
                Message = $line
            }
        }
    }

    $errorMessage = ""
    if ($cases.Count -eq 0) {
        $status = "pass"
        if ($exitCode -ne 0) {
            $status = "failure"
            $errorMessage = "$Name failed with exit code $exitCode"
        }
        $cases += [PSCustomObject]@{
            Name    = "$Name binary"
            Status  = $status
            Message = $errorMessage
        }
    }

    New-JUnitReport -Path $junit -SuiteName $Name -Cases $cases -ErrorMessage $errorMessage

    if ($exitCode -ne 0) {
        throw "$Name failed with exit code $exitCode"
    }
}

Push-Location $binDir
$failures = @()

try {
    try {
        Invoke-GinkgoTest -Name "win-sshproxy" -Executable (Join-Path $binDir "win-sshproxy.test.exe") -Arguments @()
    } catch {
        Write-Host $_
        $failures += $_
    }

    try {
        Invoke-GinkgoTest -Name "gvproxy" -Executable (Join-Path $binDir "gvproxy.test.exe") -Arguments @()
    } catch {
        Write-Host $_
        $failures += $_
    }

    try {
        Invoke-GoTest -Name "sshclient" -Executable (Join-Path $binDir "sshclient.test.exe") -Arguments @()
    } catch {
        Write-Host $_
        $failures += $_
    }
} finally {
    Pop-Location
}

if ($failures.Count -gt 0) {
    exit 1
}

exit 0
