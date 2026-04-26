param(
    [switch]$Apply,
    [switch]$Aggressive
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$refDir = Split-Path -Parent $scriptDir

$targets = @(
    "logs/.params_bench_tmp",
    "logs/.bench4_tmp",
    "__pycache__",
    "scripts/__pycache__"
)

if ($Aggressive) {
    # Aggressive mode includes known generated temp header used during param search.
    $targets += "params/params-sphincs-poseidon2-searchtmp.h"
}

Write-Host "Cleanup mode: " -NoNewline
if ($Apply) { Write-Host "APPLY (will delete)" } else { Write-Host "DRY-RUN (no deletion)" }
Write-Host "Aggressive mode: $Aggressive"
Write-Host ""

foreach ($rel in $targets) {
    $abs = Join-Path $refDir $rel
    if (Test-Path $abs) {
        Write-Host "[TARGET] $rel"
        if ($Apply) {
            Remove-Item -Recurse -Force $abs
            Write-Host "  -> deleted"
        }
    } else {
        Write-Host "[SKIP] $rel (not found)"
    }
}

Write-Host ""
if (-not $Apply) {
    Write-Host "Dry-run finished. Re-run with -Apply to execute deletion."
}
