-- =============================================================================
-- FrostStream NIDS - Phase 3: Snowpark Registration & Orchestration
--   * Stored Procedures  : SP_RUN_NIDS_INFERENCE, SP_RUN_DRIFT_MONITOR
--   * SOAR UDF            : EXTERNAL_MITIGATE_IP (External Network Access -> API Gateway)
--   * Orchestration Tasks : INFERENCE_TASK, DRIFT_MONITOR_TASK, SOAR_DISPATCH_TASK
--   * CDC Stream          : NIDS_ALERTS_STREAM
--
-- Code upload note
--   The Python sources are packaged into a single archive preserving the
--   `src/` and `data/` package layout (so `from src.models.constants import ...`
--   resolves inside the Snowpark runtime). Build + upload automation:
--       pwsh ./snowflake_setup/deploy_phase3.ps1
--   which produces  .cache/snowpark_code.zip  and PUTs it to
--   @CORE.SNOWPARK_CODE_STAGE via `tools/deploy_snowpark_code.py`.
--
-- Handler format for a packaged import:
--   IMPORTS = ('@CORE.SNOWPARK_CODE_STAGE/snowpark_code.zip')
--   HANDLER = 'src.models.inference.sp_run_nids_inference'
-- =============================================================================

USE DATABASE FROSTSTREAM_NIDS;
USE SCHEMA CORE;

-- -----------------------------------------------------------------------------
-- 1. Stored Procedure: NIDS Inference
--    Scores unprocessed rows in CORE.FLOW_FEATURES (batch of up to 5000),
--    writes alerts to CORE.NIDS_ALERTS, and marks rows processed.
--    See src/models/inference.py::sp_run_nids_inference
-- -----------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE CORE.SP_RUN_NIDS_INFERENCE()
  RETURNS STRING
  LANGUAGE PYTHON
  RUNTIME_VERSION = '3.10'
  PACKAGES = ('snowflake-snowpark-python', 'scikit-learn', 'xgboost', 'joblib', 'pandas')
  IMPORTS = ('@CORE.SNOWPARK_CODE_STAGE/snowpark_code.zip')
  HANDLER = 'src.models.inference.sp_run_nids_inference'
  COMMENT = 'Scores unprocessed NSL-KDD flows; writes severity/zero-day alerts to NIDS_ALERTS';

-- -----------------------------------------------------------------------------
-- 2. Stored Procedure: Drift Monitor
--    Computes per-feature PSI against the registered baseline distribution and
--    stores CORE.DRIFT_REPORTS (alerting on max PSI > 0.25).
--    See src/models/drift_monitor.py::sp_run_drift_monitor
-- -----------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE CORE.SP_RUN_DRIFT_MONITOR()
  RETURNS STRING
  LANGUAGE PYTHON
  RUNTIME_VERSION = '3.10'
  PACKAGES = ('snowflake-snowpark-python', 'scikit-learn', 'xgboost', 'joblib', 'pandas')
  IMPORTS = ('@CORE.SNOWPARK_CODE_STAGE/snowpark_code.zip')
  HANDLER = 'src.models.drift_monitor.sp_run_drift_monitor'
  COMMENT = 'Hourly Population Stability Index (PSI) drift detection vs MODEL_REGISTRY baseline';

-- -----------------------------------------------------------------------------
-- 3. SOAR External Function (Snowflake -> API Gateway -> mitigator Lambda)
--    NOTE: <AWS_ACCOUNT_ID> and <region> are substituted automatically from
--    .env by tools/deploy_cloud.py. <api-id> MUST be replaced manually with
--    the MitigatorHttpApi id (from `sam deploy` output MitigatorApiUrl) before
--    deploying with --enable-soar. The IAM role must exist in AWS (Phase 5).
--
--    NOTE: External Network Access (UDF) is not available on trial accounts.
--    This uses External Function which requires cross-account IAM AssumeRole.
--    If blocked by SCP, the AWS admin must whitelist Snowflake's principal:
--    arn:aws:iam::291216788687:user/58892000-s
-- -----------------------------------------------------------------------------
-- [SOAR_API_START]
-- API Integration (idempotent - doesn't regenerate ExternalId on update)
CREATE API INTEGRATION IF NOT EXISTS SOAR_API_INTEGRATION
  API_PROVIDER = aws_api_gateway
  API_AWS_ROLE_ARN = 'arn:aws:iam::<AWS_ACCOUNT_ID>:role/SnowflakeSOARFunctionRole'
  API_ALLOWED_PREFIXES = ('https://<api-id>.execute-api.<region>.amazonaws.com/prod/mitigate')
  ENABLED = TRUE
  COMMENT = 'Enables Snowflake external function calls to the Phase 5 mitigator Lambda';

-- Update allowed prefixes if the integration already exists (URL change)
ALTER API INTEGRATION SOAR_API_INTEGRATION SET API_ALLOWED_PREFIXES = ('https://<api-id>.execute-api.<region>.amazonaws.com/prod/mitigate');

-- External function used by SOAR_DISPATCH_TASK to block a hostile source IP.
CREATE OR REPLACE EXTERNAL FUNCTION CORE.EXTERNAL_MITIGATE_IP(
    SRC_IP VARCHAR
  , ALERT_ID VARCHAR
  , CONFIDENCE FLOAT
  , ATTACK_TYPE VARCHAR
)
  RETURNS VARIANT
  API_INTEGRATION = SOAR_API_INTEGRATION
  AS 'https://<api-id>.execute-api.<region>.amazonaws.com/prod/mitigate';
-- [SOAR_API_END]

-- -----------------------------------------------------------------------------
-- 4. CDC Stream on NIDS_ALERTS (consumed by SOAR_DISPATCH_TASK)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE STREAM CORE.NIDS_ALERTS_STREAM
  ON TABLE CORE.NIDS_ALERTS
  APPEND_ONLY = TRUE
  COMMENT = 'CDC stream on new alerts, consumed by SOAR_DISPATCH_TASK';

-- -----------------------------------------------------------------------------
-- 5. Orchestration Tasks
-- -----------------------------------------------------------------------------
-- 5a. Inference task - every minute, scores whatever the flatten task produced.
CREATE OR REPLACE TASK CORE.INFERENCE_TASK
  WAREHOUSE = NIDS_ANALYTICS_WH
  SCHEDULE = '1 MINUTE'
  COMMENT = 'Minute-level scoring of unprocessed FLOW_FEATURES rows'
AS
  CALL CORE.SP_RUN_NIDS_INFERENCE();

ALTER TASK INFERENCE_TASK RESUME;

-- 5b. Drift monitor task - hourly, evaluates live 1h window vs baseline.
CREATE OR REPLACE TASK CORE.DRIFT_MONITOR_TASK
  WAREHOUSE = NIDS_ANALYTICS_WH
  SCHEDULE = 'USING CRON 0 * * * * UTC'
  COMMENT = 'Hourly PSI drift check; writes CORE.DRIFT_REPORTS and HIGH drift alerts'
AS
  CALL CORE.SP_RUN_DRIFT_MONITOR();

ALTER TASK DRIFT_MONITOR_TASK RESUME;

-- 5c. SOAR dispatch task - reacts to new CRITICAL/HIGH alerts with confidence
--     > 0.95 and MITIGATION_STATUS = PENDING. Each row is pushed through
--     EXTERNAL_MITIGATE_IP; the returned status is written back to the alert
--     in the same statement (single MERGE consumes the stream atomically).
--
--     IMPORTANT: leave this task SUSPENDED until the Phase 5 API Gateway +
--     mitigator Lambda are live; otherwise the task will fail on the first
--     qualifying alert. Resume once deployed:
--         ALTER TASK SOAR_DISPATCH_TASK RESUME;
-- [SOAR_TASK_START]
CREATE OR REPLACE TASK CORE.SOAR_DISPATCH_TASK
  WAREHOUSE = NIDS_ANALYTICS_WH
  SCHEDULE = '1 MINUTE'
  COMMENT = 'Dispatches qualifying alerts to the SOAR mitigator and records the outcome'
  WHEN SYSTEM$STREAM_HAS_DATA('CORE.NIDS_ALERTS_STREAM')
AS
  MERGE INTO CORE.NIDS_ALERTS AS a
  USING (
    SELECT
        ALERT_ID
      , SRC_IP
      , CONFIDENCE
      , ATTACK_TYPE
      , EXTERNAL_MITIGATE_IP(SRC_IP, ALERT_ID, CONFIDENCE, ATTACK_TYPE) AS RESPONSE
    FROM CORE.NIDS_ALERTS_STREAM
    WHERE SEVERITY IN ('CRITICAL', 'HIGH')
      AND CONFIDENCE > 0.95
      AND MITIGATION_STATUS = 'PENDING'
  ) AS s
  ON a.ALERT_ID = s.ALERT_ID
  WHEN MATCHED THEN UPDATE SET
      MITIGATION_STATUS = COALESCE(GET_PATH(s.RESPONSE, 'status')::VARCHAR, 'ACTIONED'),
      MITIGATED_AT = CURRENT_TIMESTAMP(),
      MITIGATION_DETAILS = s.RESPONSE;
-- [SOAR_TASK_END]

-- NOTE: deliberately NOT resumed - see comment above.

-- =============================================================================
-- Deployment Notes
-- =============================================================================
-- 1. Build + upload code package, then run this file:
--      pwsh ./snowflake_setup/deploy_phase3.ps1
-- 2. Register trained model artifacts to @CORE.MODEL_STAGE (run in CLOUD mode):
--      EXECUTION_MODE=CLOUD python -m src.models.train --samples 8000
-- 3. Smoke test (after models exist on MODEL_STAGE):
--      CALL CORE.SP_RUN_NIDS_INFERENCE();
--      CALL CORE.SP_RUN_DRIFT_MONITOR();
-- 4. Once Phase 5 (API Gateway + Lambda) is deployed, replace <api-id> and <region>
--    placeholders above, re-run this file with --enable-soar, then:
--      ALTER TASK SOAR_DISPATCH_TASK RESUME;
-- =============================================================================