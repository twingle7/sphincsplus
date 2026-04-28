$ErrorActionPreference = "Stop"
if ($null -ne (Get-Variable PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue)) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$root = Split-Path -Parent $PSScriptRoot
$testExe = Join-Path $root "test\\hash_profile_verify.exe"

function Find-Gcc {
    $candidates = @(
        "D:\\x86_64-8.1.0-release-posix-seh-rt_v6-rev0\\mingw64\\bin\\gcc.exe",
        "C:\\msys64\\mingw64\\bin\\gcc.exe"
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    $cmd = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    throw "gcc.exe not found"
}

function Get-Sources([string]$params) {
    $common = @(
        "address.c", "merkle.c", "wots.c", "wotsx1.c",
        "utils.c", "utilsx1.c", "fors.c", "sign.c", "hash_profile.c",
        "test/hash_profile_verify.c", "test/hash_profile_randombytes.c"
    )

    if ($params -like "*sha2*") {
        return $common + @("sha2.c", "hash_sha2.c", "thash_sha2_simple.c")
    }
    if ($params -like "*shake*") {
        return $common + @("fips202.c", "hash_shake.c", "thash_shake_simple.c")
    }
    if ($params -like "*haraka*") {
        return $common + @("haraka.c", "hash_haraka.c", "thash_haraka_simple.c")
    }
    if ($params -like "*poseidon2*") {
        return $common + @(
            "fips202.c", "poseidon2.c", "hash_poseidon2.c", "thash_poseidon2_simple.c",
            "hash_poseidon2_adapter.c", "bsig_poseidon2_v0.c",
            "show/show_poseidon2_v1.c", "show/show_poseidon2.c", "show/protocol_poseidon2_v1.c",
            "stark/witness_builder.c", "stark/air_poseidon2_perm.c", "stark/air_poseidon2_sponge.c",
            "stark/air_hashcall.c", "stark/air_verify_minimal.c", "stark/air_verify_full.c",
            "stark/pi_f_format_v1.c", "stark/pi_f_format_v2.c", "stark/pi_f_format.c",
            "stark/prover_v1.c", "stark/verifier_v1.c", "stark/relation_migration_v1.c",
            "stark/ffi_v1.c", "stark/ffi.c", "stark/stats_v1.c", "stark/stats.c"
        )
    }

    throw "Unsupported PARAMS: $params"
}

function Get-BackendDefine([string]$params) {
    if ($params -like "*sha2*") { return "SPX_BACKEND_SHA2=1" }
    if ($params -like "*shake*") { return "SPX_BACKEND_SHAKE=1" }
    if ($params -like "*haraka*") { return "SPX_BACKEND_HARAKA=1" }
    if ($params -like "*poseidon2*") { return "SPX_BACKEND_POSEIDON2=1" }
    throw "Unsupported PARAMS: $params"
}

function Build-And-Run([string]$gcc, [string]$params) {
    $sources = Get-Sources $params
    $backendDefine = Get-BackendDefine $params
    & $gcc `
        -Wall -Wextra -Wpedantic -O3 -std=c99 -Wconversion -Wmissing-prototypes `
        "-DPARAMS=$params" "-D$backendDefine" `
        -o $testExe `
        @sources

    if ($LASTEXITCODE -ne 0) {
        throw "Build failed for $params"
    }

    $runOutput = & $testExe
    if ($LASTEXITCODE -ne 0) {
        $runOutput | Out-String | Write-Host
        throw "Run failed for $params"
    }

    return ($runOutput | Select-Object -Last 1)
}

function Parse-Field([string]$line, [string]$key) {
    $m = [regex]::Match($line, "(?:^| )$key=([^ ]+)")
    if (-not $m.Success) {
        throw "Missing field $key in: $line"
    }
    return $m.Groups[1].Value
}

$gcc = Find-Gcc
$baselineLine = Build-And-Run $gcc "sphincs-sha2-192s"
$poseidonLine = Build-And-Run $gcc "sphincs-poseidon2-192s"

$baselineConstraints = [double](Parse-Field $baselineLine "estimated_constraints")
$poseidonConstraints = [double](Parse-Field $poseidonLine "estimated_constraints")
$drop = $baselineConstraints - $poseidonConstraints
$dropPct = 0.0

if ($baselineConstraints -gt 0) {
    $dropPct = 100.0 * $drop / $baselineConstraints
}

Write-Output $baselineLine
Write-Output $poseidonLine
Write-Output ("hash_profile_compare: baseline=sphincs-sha2-192s poseidon=sphincs-poseidon2-192s baseline_constraints={0:0} poseidon_constraints={1:0} drop={2:0} drop_pct={3:N2}" -f $baselineConstraints, $poseidonConstraints, $drop, $dropPct)
