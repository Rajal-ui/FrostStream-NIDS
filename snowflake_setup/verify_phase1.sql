-- =============================================================================
-- FrostStream NIDS - Phase 1 Validation Queries
-- Run AFTER 01_tables.sql and 02_snowpipe.sql:
--   snow sql -f snowflake_setup/verify_phase1.sql
-- Expected outcomes are annotated inline. Every query must return no error.
-- =============================================================================

USE DATABASE FROSTSTREAM_NIDS;
USE SCHEMA CORE;

-- -----------------------------------------------------------------------------
-- 1. Database, schema, warehouses
-- -----------------------------------------------------------------------------
SHOW DATABASES LIKE 'FROSTSTREAM_NIDS';           -- expect 1 row
SHOW SCHEMAS IN DATABASE FROSTSTREAM_NIDS;        -- expect CORE (at minimum)
SHOW WAREHOUSES LIKE 'NIDS%';                     -- expect NIDS_INGEST_WH, NIDS_ANALYTICS_WH

-- -----------------------------------------------------------------------------
-- 2. Tables exist with expected objects
-- -----------------------------------------------------------------------------
SHOW TABLES IN SCHEMA CORE;                       -- expect RAW_FLOW_LANDING, FLOW_FEATURES, NIDS_ALERTS, MODEL_REGISTRY, DRIFT_REPORTS

SELECT 'FLOW_FEATURES_columns' AS check_name, COUNT(*) AS column_count
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'CORE' AND TABLE_NAME = 'FLOW_FEATURES';
-- expect 45+ (FLOW_ID + 9 ids + 41 NSL-KDD features + PROCESSED_FLAG/CREATED_AT/PROCESSED_AT)

SELECT 'NIDS_ALERTS_columns' AS check_name, COUNT(*) AS column_count
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'CORE' AND TABLE_NAME = 'NIDS_ALERTS';

SELECT 'FLOW_FEATURES_synthetic' AS check_name, IS_SYNTHETIC, COUNT(*) AS row_count
FROM FLOW_FEATURES
GROUP BY IS_SYNTHETIC
ORDER BY IS_SYNTHETIC;

SELECT 'NIDS_ALERTS_synthetic' AS check_name, IS_SYNTHETIC, COUNT(*) AS row_count
FROM NIDS_ALERTS
GROUP BY IS_SYNTHETIC
ORDER BY IS_SYNTHETIC;

SHOW VIEWS IN SCHEMA CORE;

-- -----------------------------------------------------------------------------
-- 3. Stages
-- -----------------------------------------------------------------------------
SHOW STAGES IN SCHEMA CORE;                       -- expect MODEL_STAGE, SNOWPARK_CODE_STAGE, S3_FLOW_STAGE

-- -----------------------------------------------------------------------------
-- 4. Storage integration (capture the values needed for the S3 bucket policy)
-- -----------------------------------------------------------------------------
DESCRIBE INTEGRATION S3_FLOW_INTEGRATION;         -- copy STORAGE_AWS_IAM_USER_ARN + STORAGE_AWS_EXTERNAL_ID

-- -----------------------------------------------------------------------------
-- 5. Snowpipe status
-- -----------------------------------------------------------------------------
SELECT SYSTEM$PIPE_STATUS('CORE.PIPE_RAW_FLOW');  -- expect {"executionState":"RUNNING", ...} after AWS event notifications wired

-- -----------------------------------------------------------------------------
-- 6. CDC streams
-- -----------------------------------------------------------------------------
SHOW STREAMS IN SCHEMA CORE;                      -- expect RAW_FLOW_STREAM, FLOW_FEATURES_STREAM

-- -----------------------------------------------------------------------------
-- 7. Tasks (state)
-- -----------------------------------------------------------------------------
SHOW TASKS IN SCHEMA CORE;                        -- expect FLATTEN_FLOW_TASK SCHEDULED/RUNNING (created + resumed)

-- -----------------------------------------------------------------------------
-- 8. Clustering keys applied (replaces the non-functional CREATE INDEX from the
--    original draft; confirm micro-partition pruning keys are active)
-- -----------------------------------------------------------------------------
SELECT TABLE_SCHEMA, TABLE_NAME, CLUSTERING_KEY
FROM FROSTSTREAM_NIDS.INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = 'CORE' AND CLUSTERING_KEY IS NOT NULL;
-- expect FLOW_FEATURES (PROCESSED_FLAG, CREATED_AT), NIDS_ALERTS (SEVERITY, MITIGATION_STATUS), DRIFT_REPORTS (CHECK_TIMESTAMP)

-- -----------------------------------------------------------------------------
-- 9. Row-count sanity (all should be zero immediately after deployment)
-- -----------------------------------------------------------------------------
SELECT 'RAW_FLOW_LANDING' AS table_name, COUNT(*) AS row_count FROM RAW_FLOW_LANDING
UNION ALL SELECT 'FLOW_FEATURES', COUNT(*) FROM FLOW_FEATURES
UNION ALL SELECT 'NIDS_ALERTS', COUNT(*) FROM NIDS_ALERTS
UNION ALL SELECT 'MODEL_REGISTRY', COUNT(*) FROM MODEL_REGISTRY
UNION ALL SELECT 'DRIFT_REPORTS', COUNT(*) FROM DRIFT_REPORTS;

-- =============================================================================
-- End of verify_phase1.sql
-- =============================================================================