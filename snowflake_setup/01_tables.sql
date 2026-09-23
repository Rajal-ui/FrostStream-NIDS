-- =============================================================================
-- FrostStream NIDS - Phase 1: Snowflake Foundation DDL
-- Database, Schema, Warehouses, Tables, Stages
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Database & Schema Initialization
-- -----------------------------------------------------------------------------
CREATE DATABASE IF NOT EXISTS FROSTSTREAM_NIDS;
USE DATABASE FROSTSTREAM_NIDS;
CREATE SCHEMA IF NOT EXISTS CORE;
USE SCHEMA CORE;

-- -----------------------------------------------------------------------------
-- Compute Warehouses
-- -----------------------------------------------------------------------------
-- Ingestion warehouse (XS, auto-suspend 60s) - for Snowpipe/flattening tasks
CREATE WAREHOUSE IF NOT EXISTS NIDS_INGEST_WH
  WITH WAREHOUSE_SIZE = 'XSMALL'
  AUTO_SUSPEND = 60
  AUTO_RESUME = TRUE
  INITIALLY_SUSPENDED = TRUE
  COMMENT = 'Warehouse for data ingestion and flattening tasks';

-- Analytics warehouse (S, auto-suspend 120s) - for ML inference, drift monitoring
CREATE WAREHOUSE IF NOT EXISTS NIDS_ANALYTICS_WH
  WITH WAREHOUSE_SIZE = 'SMALL'
  AUTO_SUSPEND = 120
  AUTO_RESUME = TRUE
  INITIALLY_SUSPENDED = TRUE
  COMMENT = 'Warehouse for ML inference, drift monitoring, and SOAR tasks';

-- -----------------------------------------------------------------------------
-- 1. RAW_FLOW_LANDING: Staging table for raw VPC flow logs / Scapy captures
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS RAW_FLOW_LANDING (
    RAW_ID VARCHAR(64) NOT NULL,
    INGESTION_TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    RECORD_CONTENT VARIANT NOT NULL,
    FILE_NAME VARCHAR(512),
    FILE_ROW_NUMBER NUMBER,
    PRIMARY KEY (RAW_ID)
) COMMENT = 'Raw landing zone for flow logs from Kinesis Firehose / S3 / Scapy';

-- -----------------------------------------------------------------------------
-- 2. FLOW_FEATURES: Flattened typed table matching NSL-KDD schema (41 features + IDs)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS FLOW_FEATURES (
    -- Flow identifiers
    FLOW_ID VARCHAR(64) NOT NULL,
    SRC_IP VARCHAR(45) NOT NULL,
    DST_IP VARCHAR(45) NOT NULL,
    SRC_PORT NUMBER(5,0),
    DST_PORT NUMBER(5,0),
    PROTOCOL VARCHAR(10),
    
    -- NSL-KDD 41 Features
    DURATION NUMBER(10,0),
    PROTOCOL_TYPE VARCHAR(10),
    SERVICE VARCHAR(50),
    FLAG VARCHAR(10),
    SRC_BYTES NUMBER(20,0),
    DST_BYTES NUMBER(20,0),
    LAND NUMBER(1,0),
    WRONG_FRAGMENT NUMBER(10,0),
    URGENT NUMBER(10,0),
    HOT NUMBER(10,0),
    NUM_FAILED_LOGINS NUMBER(10,0),
    LOGGED_IN NUMBER(1,0),
    NUM_COMPROMISED NUMBER(10,0),
    ROOT_SHELL NUMBER(1,0),
    SU_ATTEMPTED NUMBER(1,0),
    NUM_ROOT NUMBER(10,0),
    NUM_FILE_CREATIONS NUMBER(10,0),
    NUM_SHELLS NUMBER(10,0),
    NUM_ACCESS_FILES NUMBER(10,0),
    NUM_OUTBOUND_CMDS NUMBER(10,0),
    IS_HOST_LOGIN NUMBER(1,0),
    IS_GUEST_LOGIN NUMBER(1,0),
    COUNT NUMBER(10,0),
    SRV_COUNT NUMBER(10,0),
    SERROR_RATE FLOAT,
    SRV_SERROR_RATE FLOAT,
    RERROR_RATE FLOAT,
    SRV_RERROR_RATE FLOAT,
    SAME_SRV_RATE FLOAT,
    DIFF_SRV_RATE FLOAT,
    SRV_DIFF_HOST_RATE FLOAT,
    DST_HOST_COUNT NUMBER(10,0),
    DST_HOST_SRV_COUNT NUMBER(10,0),
    DST_HOST_SAME_SRV_RATE FLOAT,
    DST_HOST_DIFF_SRV_RATE FLOAT,
    DST_HOST_SAME_SRC_PORT_RATE FLOAT,
    DST_HOST_SRV_DIFF_HOST_RATE FLOAT,
    DST_HOST_SERROR_RATE FLOAT,
    DST_HOST_SRV_SERROR_RATE FLOAT,
    DST_HOST_RERROR_RATE FLOAT,
    DST_HOST_SRV_RERROR_RATE FLOAT,
    
    -- Processing metadata
    PROCESSED_FLAG BOOLEAN DEFAULT FALSE,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    PROCESSED_AT TIMESTAMP_NTZ,
    PRIMARY KEY (FLOW_ID)
) COMMENT = 'Flattened NSL-KDD compatible flow features ready for ML inference';

-- Index for efficient unprocessed record queries
CREATE INDEX IF NOT EXISTS IDX_FLOW_FEATURES_UNPROCESSED ON FLOW_FEATURES(PROCESSED_FLAG, CREATED_AT);

-- -----------------------------------------------------------------------------
-- 3. NIDS_ALERTS: Alert store with mitigation tracking
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS NIDS_ALERTS (
    ALERT_ID VARCHAR(64) NOT NULL,
    TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    FLOW_ID VARCHAR(64),
    SRC_IP VARCHAR(45) NOT NULL,
    DST_IP VARCHAR(45) NOT NULL,
    SRC_PORT NUMBER(5,0),
    DST_PORT NUMBER(5,0),
    ATTACK_TYPE VARCHAR(20) NOT NULL,  -- Normal, DoS, Probe, R2L, U2R, MODEL_DRIFT_ALERT
    CONFIDENCE FLOAT NOT NULL,
    ANOMALY_SCORE FLOAT,
    SEVERITY VARCHAR(20) NOT NULL,     -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    IS_ZERO_DAY_SUSPECT BOOLEAN DEFAULT FALSE,
    MITIGATION_STATUS VARCHAR(20) DEFAULT 'PENDING',  -- PENDING, ACTIONED, SUPPRESSED, EXPIRED, FAILED
    MITIGATED_AT TIMESTAMP_NTZ,
    MITIGATION_DETAILS VARIANT,
    RAW_FEATURES VARIANT,
    PRIMARY KEY (ALERT_ID)
) COMMENT = 'NIDS alert store with SOAR mitigation tracking';

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS IDX_NIDS_ALERTS_TIMESTAMP ON NIDS_ALERTS(TIMESTAMP DESC);
CREATE INDEX IF NOT EXISTS IDX_NIDS_ALERTS_SEVERITY ON NIDS_ALERTS(SEVERITY, MITIGATION_STATUS);
CREATE INDEX IF NOT EXISTS IDX_NIDS_ALERTS_SRC_IP ON NIDS_ALERTS(SRC_IP, TIMESTAMP DESC);

-- -----------------------------------------------------------------------------
-- 4. MODEL_REGISTRY: Tracks active ensemble & anomaly models
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS MODEL_REGISTRY (
    MODEL_NAME VARCHAR(100) NOT NULL,
    VERSION VARCHAR(50) NOT NULL,
    STAGE_PATH VARCHAR(512) NOT NULL,        -- e.g., @CORE.MODEL_STAGE/ensemble_classifier_v1.joblib
    MODEL_TYPE VARCHAR(50) NOT NULL,         -- ENSEMBLE_CLASSIFIER, ISOLATION_FOREST, PREPROCESSOR
    TRAINING_METRICS VARIANT,                -- {accuracy, precision, recall, f1, per_class_metrics}
    BASELINE_DISTRIBUTION VARIANT,           -- Feature distribution stats for PSI drift detection
    IS_ACTIVE BOOLEAN DEFAULT FALSE,
    REGISTERED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    ACTIVATED_AT TIMESTAMP_NTZ,
    DEACTIVATED_AT TIMESTAMP_NTZ,
    PRIMARY KEY (MODEL_NAME, VERSION)
) COMMENT = 'Model registry for versioned ML artifacts and drift baselines';

-- -----------------------------------------------------------------------------
-- 5. DRIFT_REPORTS: Stores hourly PSI metrics
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS DRIFT_REPORTS (
    REPORT_ID VARCHAR(64) NOT NULL,
    CHECK_TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    WINDOW_START TIMESTAMP_NTZ NOT NULL,
    WINDOW_END TIMESTAMP_NTZ NOT NULL,
    MAX_PSI FLOAT NOT NULL,
    DRIFTED_FEATURES VARIANT,                -- Array of {feature, psi, threshold_exceeded}
    FEATURE_PSI_DETAILS VARIANT,             -- Full PSI breakdown per feature
    STATUS VARCHAR(20) NOT NULL,             -- OK, WARNING, ALERT
    PRIMARY KEY (REPORT_ID)
) COMMENT = 'Hourly Population Stability Index drift monitoring reports';

-- Index for time-series queries
CREATE INDEX IF NOT EXISTS IDX_DRIFT_REPORTS_TIMESTAMP ON DRIFT_REPORTS(CHECK_TIMESTAMP DESC);

-- -----------------------------------------------------------------------------
-- Internal Stages for Model Artifacts & Snowpark Code
-- -----------------------------------------------------------------------------
CREATE STAGE IF NOT EXISTS MODEL_STAGE
  ENCRYPTION = (TYPE = 'SNOWFLAKE_SSE')
  COMMENT = 'Stage for .joblib model artifacts (ensemble, isolation_forest, preprocessor, baseline)';

CREATE STAGE IF NOT EXISTS SNOWPARK_CODE_STAGE
  ENCRYPTION = (TYPE = 'SNOWFLAKE_SSE')
  COMMENT = 'Stage for Python SPROC source files (inference.py, drift_monitor.py, etc.)';

-- -----------------------------------------------------------------------------
-- Grants for Service Roles (adjust as needed for your environment)
-- -----------------------------------------------------------------------------
-- GRANT USAGE ON WAREHOUSE NIDS_INGEST_WH TO ROLE NIDS_SERVICE_ROLE;
-- GRANT USAGE ON WAREHOUSE NIDS_ANALYTICS_WH TO ROLE NIDS_SERVICE_ROLE;
-- GRANT ALL ON SCHEMA CORE TO ROLE NIDS_SERVICE_ROLE;
-- GRANT ALL ON ALL TABLES IN SCHEMA CORE TO ROLE NIDS_SERVICE_ROLE;
-- GRANT READ, WRITE ON STAGE MODEL_STAGE TO ROLE NIDS_SERVICE_ROLE;
-- GRANT READ, WRITE ON STAGE SNOWPARK_CODE_STAGE TO ROLE NIDS_SERVICE_ROLE;

-- =============================================================================
-- End of 01_tables.sql
-- =============================================================================