<# =============================================================================
FrostStream NIDS - Phase 3 Deployment
Packages the Snowpark code (src/ + data/) into snowpark_code.zip, uploads it to
@CORE.SNOWPARK_CODE_STAGE, then registers the SPROCs, external function and
orchestration tasks via the Snowflake CLI.

Usage:
    pwsh ./snowflake_setup/deploy_phase3.ps1 [-Connection default] [-SkipUpload]

Prerequisites:
    - Phase 1 deployed (snowflake_setup/deploy_phase1.ps1)
    - Snowflake CLI + connection profile (see deploy_phase1.ps1)
    - For --upload: CLI credentials OR `EXECUTION_MODE=CLOUD` env vars
      (SNOWFLAKE_ACCOUNT/USER/... ). Uses the venv at D:\...\venv.
============================================================================= #>
[CmdletBinding()]
param(
    [string]$Connection = 'default',
    [switch]$SkipUpload
)
$ErrorActionPreference = 'Stop'

$Root   = Split-Path -Parent $PSScriptRoot
$Setup  = $PSScriptRoot
$VenvPy = Join-Path $Root 'venv\Scripts\python.exe'
$Helper = Join-Path $Root 'tools\deploy_snowpark_code.py'
$Archive = Join-Path $Root '.cache\snowpark_code.zip'

function Invoke-SnowSql([string]$File) {
    Write-Host "`n==> snow sql -f $File" -ForegroundColor Cyan
    $out = snow sql -f $File -c $Connection 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host $out -ForegroundColor Red
        throw "Snowflake SQL step failed: $File"
    }
    Write-Host $out -ForegroundColor Green
}

Write-Host 'FrostStream NIDS - Phase 3 Deployment (Snowpark Registration)' -ForegroundColor Magenta

# --- Prerequisites -----------------------------------------------------------
if (-not (Get-Command snow -ErrorAction SilentlyContinue)) {
    throw 'Snowflake CLI (`snow`) not found on PATH.'
}
if (-not (Test-Path $Archive)) { $SkipUpload = $true }
if (-not $SkipUpload -and -not (Test-Path $VenvPy)) {
    throw "venv python not found at $VenvPy (needed for snowflake-snowpark upload)."
}

# --- 1. Build (offline) + upload code package --------------------------------
if (-not $SkipUpload) {
    Write-Host "`n==> Building + uploading Snowpark code package (venv: $VenvPy)" -ForegroundColor Cyan
    & $VenvPy $Helper --build --upload --archive $Archive
    if ($LASTEXITCODE -ne 0) { throw 'Code package build/upload failed.' }
} elseif (Test-Path $Archive) {
    Write-Host "`nSkipping upload (-SkipUpload); reusing existing $Archive" -ForegroundColor Yellow
} else {
    Write-Host "`nNo archive at $Archive - skipping upload (SPROC registration only)." -ForegroundColor Yellow
}

# --- 2. Register SPROCs, external function, tasks ----------------------------
Invoke-SnowSql (Join-Path $Setup '03_snowpark_integration.sql')

# --- 3. Validation -----------------------------------------------------------
Invoke-SnowSql (Join-Path $Setup 'verify_phase3.sql')

Write-Host "`nPhase 3 deployment completed." -ForegroundColor Green
Write-Host @'

-------------------------------------------------------------------
 Remaining steps
-------------------------------------------------------------------
1. Train + register models (CLOUD training uploads to MODEL_STAGE):
       EXECUTION_MODE=CLOUD python -m src.models.train --samples 8000
2. Smoke test (needs models on stage):
       CALL CORE.SP_RUN_NIDS_INFERENCE();
       CALL CORE.SP_RUN_DRIFT_MONITOR();
3. SOAR_DISPATCH_TASK is intentionally SUSPENDED. After Phase 5 API
   Gateway / mitigator Lambda is deployed, replace the <placeholder>
   values in 03_snowpark_integration.sql, re-run this script, then:
       ALTER TASK CORE.SOAR_DISPATCH_TASK RESUME;
-------------------------------------------------------------------
'@ -ForegroundColor Yellow