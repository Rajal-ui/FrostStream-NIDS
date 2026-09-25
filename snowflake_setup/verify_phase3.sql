-- =============================================================================
-- FrostStream NIDS - Phase 3 Validation Queries
-- Run AFTER 03_snowpark_integration.sql (and after the code package upload):
--   snow sql -f snowflake_setup/verify_phase3.sql
-- Expected outcome annotated inline; every query must return without error.
-- =============================================================================

USE DATABASE FROSTSTREAM_NIDS;
USE SCHEMA CORE;

-- -----------------------------------------------------------------------------
-- 1. Staged Python code package (must list snowpark_code.zip)
-- -----------------------------------------------------------------------------
LIST @CORE.SNOWPARK_CODE_STAGE;

-- -----------------------------------------------------------------------------
-- 2. Stored procedures
-- -----------------------------------------------------------------------------
SHOW PROCEDURES IN SCHEMA CORE;   -- expect SP_RUN_NIDS_INFERENCE, SP_RUN_DRIFT_MONITOR

-- Verify the registered handlers reference the packaged entrypoints
DESCRIBE PROCEDURE CORE.SP_RUN_NIDS_INFERENCE();
DESCRIBE PROCEDURE CORE.SP_RUN_DRIFT_MONITOR();

-- -----------------------------------------------------------------------------
-- 3. External function + API integration
-- -----------------------------------------------------------------------------
SHOW EXTERNAL FUNCTIONS IN SCHEMA CORE;           -- expect EXTERNAL_MITIGATE_IP
SHOW API INTEGRATIONS LIKE 'SOAR_API_INTEGRATION';

-- -----------------------------------------------------------------------------
-- 4. Stream + tasks
-- -----------------------------------------------------------------------------
SHOW STREAMS LIKE 'NIDS_ALERTS_STREAM';
SHOW TASKS IN SCHEMA CORE;                        -- expect INFERENCE_TASK (resumed),
                                                  -- DRIFT_MONITOR_TASK (resumed),
                                                  -- SOAR_DISPATCH_TASK (suspended)

-- -----------------------------------------------------------------------------
-- 5. Model artifacts on the model stage (required by inference/drift at runtime)
-- -----------------------------------------------------------------------------
LIST @CORE.MODEL_STAGE;                           -- expect 4 .joblib/.json files after CLOUD training

-- -----------------------------------------------------------------------------
-- 6. Smoke tests (only safe once models are staged; the SPROC returns
--    "scored=0 rows..." when there is nothing to score / drift to check)
-- -----------------------------------------------------------------------------
-- CALL CORE.SP_RUN_NIDS_INFERENCE();
-- CALL CORE.SP_RUN_DRIFT_MONITOR();
--
-- End-to-end check after a synthetic attack replay:
--   SELECT SEVERITY, MITIGATION_STATUS, COUNT(*) FROM CORE.LIVE_NIDS_ALERTS GROUP BY 1, 2;

-- =============================================================================
-- End of verify_phase3.sql
-- =============================================================================