param(
    [string]$OutputRoot = "final-results-v1",
    [switch]$CleanOutputFirst
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$refDir = Split-Path -Parent $scriptDir
$repoDir = Split-Path -Parent $refDir
$outDir = Join-Path $refDir $OutputRoot

if ($CleanOutputFirst -and (Test-Path $outDir)) {
    Remove-Item -Recurse -Force $outDir
}

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

function Copy-IfExists {
    param(
        [string]$RelativeSource,
        [string]$RelativeDest
    )
    $src = Join-Path $refDir $RelativeSource
    if (-not (Test-Path $src)) {
        Write-Host "[WARN] Missing: $RelativeSource"
        return
    }
    $dst = Join-Path $outDir $RelativeDest
    $dstDir = Split-Path -Parent $dst
    New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
    Copy-Item -Force $src $dst
    Write-Host "[COPY] $RelativeSource -> $RelativeDest"
}

# 1) parameter search (M1-M6)
$paramFiles = @(
    "logs/poseidon2-instantiation-spec-v1.md",
    "logs/params-search-raw-v1.csv",
    "logs/params-search-struct-pass-v1.csv",
    "logs/params-security-eval-v1.csv",
    "logs/params-security-pass-v1.csv",
    "logs/params-benchmark-v1-full.csv",
    "logs/params-signverify-finalists.csv",
    "logs/params-m5-merged-v1.csv",
    "logs/params-pareto-frontier-v1.csv",
    "logs/params-pareto-nonfrontier-v1.csv",
    "logs/params-pareto-v1.md",
    "logs/params-final-candidates-v1.md",
    "logs/params-budget-degradation-v1.csv",
    "logs/params-budget-degradation-v1.md",
    "logs/params-security-claim-template-v1.md",
    "logs/params-compare-with-192s-v1.csv",
    "logs/params-candidate-rank-v1.csv",
    "logs/params-primary-delta-v1.csv",
    "logs/fig-compare-sign-ms-v1.png",
    "logs/fig-compare-verify-ms-v1.png",
    "logs/fig-compare-sign-vs-zk-v1.png",
    "logs/fig-compare-multimetric-common-v1.png",
    "logs/fig-compare-candidate-heatmap-v1.png"
)
foreach ($f in $paramFiles) {
    Copy-IfExists -RelativeSource $f -RelativeDest ("param-search/" + (Split-Path -Leaf $f))
}

# 2) blind-sign / STARK / consistency / release summary
$coreExperimentFiles = @(
    "logs/benchmark-4way-local.md",
    "logs/benchmark-stark-v2-local.md",
    "logs/benchmark-stark-v2.md",
    "logs/blind-sign-e2e-v2.md",
    "logs/cross-backend-consistency-v1.md",
    "logs/m17-consistency-report-v2.md",
    "logs/release-checklist-v2.md",
    "logs/thesis-notes-stark-v2.md",
    "logs/project-final-summary-v1.md"
)
foreach ($f in $coreExperimentFiles) {
    Copy-IfExists -RelativeSource $f -RelativeDest ("core-experiments/" + (Split-Path -Leaf $f))
}

# 3) reproducible scripts
$scriptFiles = @(
    "scripts/search_params_poseidon2.py",
    "scripts/eval_security_poseidon2.py",
    "scripts/collect_benchmark_params.sh",
    "scripts/analyze_pareto_poseidon2.py",
    "scripts/plot_param_comparison.py",
    "scripts/analyze_budget_degradation_poseidon2.py",
    "scripts/collect_benchmark_4way.sh",
    "scripts/collect_benchmark_v2.sh",
    "scripts/run_m17_regression.sh"
)
foreach ($f in $scriptFiles) {
    Copy-IfExists -RelativeSource $f -RelativeDest ("scripts/" + (Split-Path -Leaf $f))
}

# 4) manifest
$manifestPath = Join-Path $outDir "MANIFEST.txt"
$allFiles = Get-ChildItem -Recurse -File $outDir | ForEach-Object {
    $_.FullName.Substring($outDir.Length + 1)
}
$manifestLines = @()
$manifestLines += "Final Results Bundle"
$manifestLines += "Generated at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$manifestLines += "Repo root: $repoDir"
$manifestLines += ""
$manifestLines += "Files:"
$manifestLines += $allFiles
Set-Content -Path $manifestPath -Value $manifestLines -Encoding UTF8

Write-Host "[DONE] Bundle directory: $outDir"
Write-Host "[DONE] Manifest: $manifestPath"
