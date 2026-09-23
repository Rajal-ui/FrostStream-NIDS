<# =============================================================================
FrostStream NIDS - Phase 1 Deployment & Validation
Deploys the Snowflake foundation DDL + Snowpipe pipeline and runs offline-facing
validation via the Snowflake CLI (`snow`).

Usage:
    pwsh ./snowflake_setup/deploy_phase1.ps1 [-Connection default] [-SkipVerify]

Prerequisites:
    - Snowflake CLI:   https://docs.snowflake.com/en/software/snowflake-cli
    - Connection profile in ~/.snowflake/config.toml (or `snow connection add`)
    - Role with privileges: CREATE DATABASE/WAREHOUSE/TABLE/STAGE/STREAM/TASK/PIPE,
      CREATE INTEGRATION (e.g. ACCOUNTADMIN)

After deploy, the printed checklist covers the AWS-side wiring (IAM role trust,
S3 bucket policy, SQS event notifications) that must be completed out-of-band,
plus the second run to confirm SYSTEM$PIPE_STATUS once S3 events flow.
============================================================================= #>
[CmdletBinding()]
param(
    [string]$Connection = 'default',
    [switch]$SkipVerify
)
$ErrorActionPreference = 'Stop'

$Root   = Split-Path -Parent $PSScriptRoot
$Setup  = $PSScriptRoot

function Invoke-SnowSql([string]$File) {
    Write-Host "`n==> snow sql -f $File" -ForegroundColor Cyan
    $out = snow sql -f $File -c $Connection 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host $out -ForegroundColor Red
        throw "Snowflake SQL step failed: $File"
    }
    Write-Host $out -ForegroundColor Green
}

Write-Host 'FrostStream NIDS - Phase 1 Deployment' -ForegroundColor Magenta

# --- Prerequisites -----------------------------------------------------------
$snow = Get-Command snow -ErrorAction SilentlyContinue
if (-not $snow) {
    throw 'Snowflake CLI (`snow`) not found on PATH. Install it, then re-run.'
    exit 1
}
$cfg = Join-Path $env:USERPROFILE '.snowflake\config.toml'
if (-not (Test-Path $cfg)) {
    throw "No Snowflake connection config found at $cfg. Run: snow connection add"
    exit 1
}

# --- 1. Foundation DDL -------------------------------------------------------
Invoke-SnowSql (Join-Path $Setup '01_tables.sql')

# --- 2. Snowpipe, streams, flattening task -----------------------------------
Invoke-SnowSql (Join-Path $Setup '02_snowpipe.sql')

# --- 3. Validation -----------------------------------------------------------
if (-not $SkipVerify) {
    Invoke-SnowSql (Join-Path $Setup 'verify_phase1.sql')
}

Write-Host "`nPhase 1 deployment completed." -ForegroundColor Green
Write-Host @'

-------------------------------------------------------------------
 Follow-up checklist (AWS side, REQUIRED before Snowpipe ingests)
-------------------------------------------------------------------
1. Create IAM role 'SnowflakeFlowLogsRole' (and target S3 bucket).
2. DESCRIBE INTEGRATION S3_FLOW_INTEGRATION (already printed in
   verify_phase1.sql output) and copy:
      STORAGE_AWS_IAM_USER_ARN   -> "AWS":  "<value>"
      STORAGE_AWS_EXTERNAL_ID    -> "sts:ExternalId": "<value>"
   into the bucket policy (actions: s3:PutObject; resource: bucket/flows/*).
3. Attach role to the bucket and enable S3 event notification
   (s3:ObjectCreated:*) -> SQS queue. Snowpipe auto-ingest publishes its
   SQS queue ARN via `SHOW PIPES LIKE 'PIPE_RAW_FLOW';`.
4. Re-run validation once traffic flows:
      snow sql -f snowflake_setup/verify_phase1.sql
   and confirm SYSTEM$PIPE_STATUS executionState = RUNNING.
-------------------------------------------------------------------
'@ -ForegroundColor Yellow