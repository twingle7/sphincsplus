param(
    [string]$PythonCmd = "python",
    [string]$OutputRoot = "final-results-v1",
    [switch]$CleanOutputFirst
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$refDir = Split-Path -Parent $scriptDir

Push-Location $refDir
try {
    Write-Host "[STEP] M6 budget degradation"
    & $PythonCmd "scripts/analyze_budget_degradation_poseidon2.py"

    Write-Host "[STEP] Multi-metric comparison refresh"
    & $PythonCmd "scripts/plot_param_comparison.py"

    Write-Host "[STEP] Package final results"
    $args = @(
        "-ExecutionPolicy", "Bypass",
        "-File", "scripts/package_final_results.ps1",
        "-OutputRoot", $OutputRoot
    )
    if ($CleanOutputFirst) {
        $args += "-CleanOutputFirst"
    }
    & powershell @args

    Write-Host "[DONE] M6 + bundle finished."
}
finally {
    Pop-Location
}
