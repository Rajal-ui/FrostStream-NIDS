-- =============================================================================
-- FrostStream NIDS - Phase 1: Snowpipe Auto-Ingest & Flattening Pipeline
-- AWS S3 Integration, Snowpipe, Streams, Flattening Task
-- =============================================================================

USE DATABASE FROSTSTREAM_NIDS;
USE SCHEMA CORE;

-- -----------------------------------------------------------------------------
-- 1. AWS Access-Key Stage for S3 Landing Bucket
-- -----------------------------------------------------------------------------
-- OPTION B (current): IAM access keys in the stage (no storage integration).
-- The AWS account blocks cross-account sts:AssumeRole from Snowflake's IAM user,
-- so the role-based flow (OPTION A) cannot be used until that is resolved.
-- Tokens <AWS_INGEST_ACCESS_KEY_ID> / <AWS_INGEST_SECRET_ACCESS_KEY> are injected
-- by tools/deploy_cloud.py from .env and refer to the dedicated low-privilege
-- IAM user 'froststream_ingest' (S3 read-only on the landing bucket).
--
-- OPTION A (future, preferred): restore a storage integration. Uncomment when
-- cross-account AssumeRole is allowed, then recreate the stage with:
--
--   CREATE STORAGE INTEGRATION IF NOT EXISTS S3_FLOW_INTEGRATION
--     TYPE = EXTERNAL_STAGE
--     STORAGE_PROVIDER = 'S3'
--     ENABLED = TRUE
--     STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::<AWS_ACCOUNT_ID>:role/SnowflakeFlowLogsRole'
--     STORAGE_ALLOWED_LOCATIONS = ('s3://<S3_BUCKET_NAME>/flows/')
--     COMMENT = 'Integration for Kinesis Firehose -> S3 -> Snowpipe flow ingestion';
--
--   CREATE OR REPLACE STAGE S3_FLOW_STAGE
--     STORAGE_INTEGRATION = S3_FLOW_INTEGRATION
--     URL = 's3://<S3_BUCKET_NAME>/flows/'
--     FILE_FORMAT = (TYPE = 'JSON' STRIP_OUTER_ARRAY = TRUE)
--     COMMENT = 'External stage for raw flow logs in S3 (JSON lines format)';

-- -----------------------------------------------------------------------------
-- 2. External Stage pointing to S3 Landing Bucket (credential-based)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE STAGE S3_FLOW_STAGE
  CREDENTIALS = (AWS_KEY_ID = '<AWS_INGEST_ACCESS_KEY_ID>' AWS_SECRET_KEY = '<AWS_INGEST_SECRET_ACCESS_KEY>')
  URL = 's3://<S3_BUCKET_NAME>/flows/'
  FILE_FORMAT = (TYPE = 'JSON' STRIP_OUTER_ARRAY = TRUE)
  COMMENT = 'External stage for raw flow logs in S3 (JSON lines format, IAM access keys)';

-- -----------------------------------------------------------------------------
-- 3. Snowpipe: Continuous Auto-Ingest from S3 Event Notifications
-- -----------------------------------------------------------------------------
-- Requires S3 Event Notification -> SQS -> Snowpipe (configured via AWS Console/CLI)
-- See: https://docs.snowflake.com/en/user-guide/data-load-snowpipe-auto-s3
CREATE OR REPLACE PIPE PIPE_RAW_FLOW
  AUTO_INGEST = TRUE
  COMMENT = 'Auto-ingest pipe: S3 JSON lines -> RAW_FLOW_LANDING table'
  AS
  COPY INTO RAW_FLOW_LANDING (RAW_ID, INGESTION_TIMESTAMP, RECORD_CONTENT, FILE_NAME, FILE_ROW_NUMBER)
  FROM (
    SELECT
      MD5(METADATA$FILENAME || '_' || METADATA$FILE_ROW_NUMBER),
      CURRENT_TIMESTAMP(),
      $1,
      METADATA$FILENAME,
      METADATA$FILE_ROW_NUMBER
    FROM @S3_FLOW_STAGE
  )
  FILE_FORMAT = (TYPE = 'JSON' STRIP_OUTER_ARRAY = TRUE)
  ON_ERROR = 'CONTINUE';

-- Check pipe status
-- SHOW PIPES LIKE 'PIPE_RAW_FLOW';
-- SELECT SYSTEM$PIPE_STATUS('PIPE_RAW_FLOW');

-- -----------------------------------------------------------------------------
-- 4. CDC Stream on Raw Landing Table
-- -----------------------------------------------------------------------------
CREATE OR REPLACE STREAM RAW_FLOW_STREAM
  ON TABLE RAW_FLOW_LANDING
  APPEND_ONLY = TRUE
  COMMENT = 'CDC stream capturing new raw flow records for flattening';

-- -----------------------------------------------------------------------------
-- 5. Flattening Task: Parse VARIANT -> Typed FLOW_FEATURES (runs every minute)
-- -----------------------------------------------------------------------------
-- This task reads from RAW_FLOW_STREAM, extracts NSL-KDD features from VARIANT,
-- and inserts typed rows into FLOW_FEATURES
CREATE OR REPLACE TASK FLATTEN_FLOW_TASK
  WAREHOUSE = NIDS_INGEST_WH
  SCHEDULE = '1 MINUTE'
  WHEN SYSTEM$STREAM_HAS_DATA('RAW_FLOW_STREAM')
  AS
  INSERT INTO FLOW_FEATURES (
    FLOW_ID, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PROTOCOL,
    DURATION, PROTOCOL_TYPE, SERVICE, FLAG, SRC_BYTES, DST_BYTES,
    LAND, WRONG_FRAGMENT, URGENT, HOT, NUM_FAILED_LOGINS, LOGGED_IN,
    NUM_COMPROMISED, ROOT_SHELL, SU_ATTEMPTED, NUM_ROOT, NUM_FILE_CREATIONS,
    NUM_SHELLS, NUM_ACCESS_FILES, NUM_OUTBOUND_CMDS, IS_HOST_LOGIN, IS_GUEST_LOGIN,
    COUNT, SRV_COUNT, SERROR_RATE, SRV_SERROR_RATE, RERROR_RATE, SRV_RERROR_RATE,
    SAME_SRV_RATE, DIFF_SRV_RATE, SRV_DIFF_HOST_RATE, DST_HOST_COUNT,
    DST_HOST_SRV_COUNT, DST_HOST_SAME_SRV_RATE, DST_HOST_DIFF_SRV_RATE,
    DST_HOST_SAME_SRC_PORT_RATE, DST_HOST_SRV_DIFF_HOST_RATE,
    DST_HOST_SERROR_RATE, DST_HOST_SRV_SERROR_RATE, DST_HOST_RERROR_RATE,
    DST_HOST_SRV_RERROR_RATE,
    IS_SYNTHETIC, PROCESSED_FLAG, CREATED_AT
  )
  SELECT
    -- Generate deterministic FLOW_ID from 5-tuple + timestamp (fall back to raw file identity)
    MD5(COALESCE(
      src_record:flow_id::VARCHAR,
      COALESCE(src_record:src_ip::VARCHAR, '') || '|' ||
      COALESCE(src_record:dst_ip::VARCHAR, '') || '|' ||
      COALESCE(src_record:src_port::VARCHAR, '') || '|' ||
      COALESCE(src_record:dst_port::VARCHAR, '') || '|' ||
      COALESCE(src_record:protocol::VARCHAR, '') || '|' ||
      COALESCE(src_record:flow_start_time::VARCHAR, src_record:timestamp::VARCHAR, RAW_ID::VARCHAR),
      RAW_ID || ':' || COALESCE(flow_index::VARCHAR, '0')
    )) AS FLOW_ID,
    
    src_record:src_ip::VARCHAR AS SRC_IP,
    src_record:dst_ip::VARCHAR AS DST_IP,
    src_record:src_port::NUMBER AS SRC_PORT,
    src_record:dst_port::NUMBER AS DST_PORT,
    src_record:protocol::VARCHAR AS PROTOCOL,
    
    -- NSL-KDD Features (with defaults for missing fields)
    COALESCE(src_record:duration::NUMBER, 0) AS DURATION,
    COALESCE(src_record:protocol_type::VARCHAR, 'tcp') AS PROTOCOL_TYPE,
    COALESCE(src_record:service::VARCHAR, 'other') AS SERVICE,
    COALESCE(src_record:flag::VARCHAR, 'SF') AS FLAG,
    COALESCE(src_record:src_bytes::NUMBER, 0) AS SRC_BYTES,
    COALESCE(src_record:dst_bytes::NUMBER, 0) AS DST_BYTES,
    COALESCE(src_record:land::NUMBER, 0) AS LAND,
    COALESCE(src_record:wrong_fragment::NUMBER, 0) AS WRONG_FRAGMENT,
    COALESCE(src_record:urgent::NUMBER, 0) AS URGENT,
    COALESCE(src_record:hot::NUMBER, 0) AS HOT,
    COALESCE(src_record:num_failed_logins::NUMBER, 0) AS NUM_FAILED_LOGINS,
    COALESCE(src_record:logged_in::NUMBER, 0) AS LOGGED_IN,
    COALESCE(src_record:num_compromised::NUMBER, 0) AS NUM_COMPROMISED,
    COALESCE(src_record:root_shell::NUMBER, 0) AS ROOT_SHELL,
    COALESCE(src_record:su_attempted::NUMBER, 0) AS SU_ATTEMPTED,
    COALESCE(src_record:num_root::NUMBER, 0) AS NUM_ROOT,
    COALESCE(src_record:num_file_creations::NUMBER, 0) AS NUM_FILE_CREATIONS,
    COALESCE(src_record:num_shells::NUMBER, 0) AS NUM_SHELLS,
    COALESCE(src_record:num_access_files::NUMBER, 0) AS NUM_ACCESS_FILES,
    COALESCE(src_record:num_outbound_cmds::NUMBER, 0) AS NUM_OUTBOUND_CMDS,
    COALESCE(src_record:is_host_login::NUMBER, 0) AS IS_HOST_LOGIN,
    COALESCE(src_record:is_guest_login::NUMBER, 0) AS IS_GUEST_LOGIN,
    COALESCE(src_record:count::NUMBER, 1) AS COUNT,
    COALESCE(src_record:srv_count::NUMBER, 1) AS SRV_COUNT,
    COALESCE(src_record:serror_rate::FLOAT, 0.0) AS SERROR_RATE,
    COALESCE(src_record:srv_serror_rate::FLOAT, 0.0) AS SRV_SERROR_RATE,
    COALESCE(src_record:rerror_rate::FLOAT, 0.0) AS RERROR_RATE,
    COALESCE(src_record:srv_rerror_rate::FLOAT, 0.0) AS SRV_RERROR_RATE,
    COALESCE(src_record:same_srv_rate::FLOAT, 1.0) AS SAME_SRV_RATE,
    COALESCE(src_record:diff_srv_rate::FLOAT, 0.0) AS DIFF_SRV_RATE,
    COALESCE(src_record:srv_diff_host_rate::FLOAT, 0.0) AS SRV_DIFF_HOST_RATE,
    COALESCE(src_record:dst_host_count::NUMBER, 255) AS DST_HOST_COUNT,
    COALESCE(src_record:dst_host_srv_count::NUMBER, 255) AS DST_HOST_SRV_COUNT,
    COALESCE(src_record:dst_host_same_srv_rate::FLOAT, 1.0) AS DST_HOST_SAME_SRV_RATE,
    COALESCE(src_record:dst_host_diff_srv_rate::FLOAT, 0.0) AS DST_HOST_DIFF_SRV_RATE,
    COALESCE(src_record:dst_host_same_src_port_rate::FLOAT, 0.0) AS DST_HOST_SAME_SRC_PORT_RATE,
    COALESCE(src_record:dst_host_srv_diff_host_rate::FLOAT, 0.0) AS DST_HOST_SRV_DIFF_HOST_RATE,
    COALESCE(src_record:dst_host_serror_rate::FLOAT, 0.0) AS DST_HOST_SERROR_RATE,
    COALESCE(src_record:dst_host_srv_serror_rate::FLOAT, 0.0) AS DST_HOST_SRV_SERROR_RATE,
    COALESCE(src_record:dst_host_rerror_rate::FLOAT, 0.0) AS DST_HOST_RERROR_RATE,
    COALESCE(src_record:dst_host_srv_rerror_rate::FLOAT, 0.0) AS DST_HOST_SRV_RERROR_RATE,

    COALESCE(FILE_NAME ILIKE 'flows/smoke_%', FALSE)
      OR COALESCE(src_record:flow_id::VARCHAR ILIKE 'smoke-%', FALSE) AS IS_SYNTHETIC,
    
    FALSE AS PROCESSED_FLAG,
    CURRENT_TIMESTAMP() AS CREATED_AT
  FROM (
    -- Normalize each landing record into a single flow object:
    --  * Direct JSON-object row        -> src_record = RECORD_CONTENT
    --  * Firehose envelope             -> src_record = f.value from array under 'records'
    -- LATERAL FLATTEN over a plain OBJECT yields one row per key (not per flow), so we
    -- flatten on PATH => 'records' with OUTER => TRUE to keep exactly one row per record.
    SELECT
      RAW_ID,
      FILE_NAME,
      COALESCE(f.value, RECORD_CONTENT) AS src_record,
      f.index AS flow_index
    FROM RAW_FLOW_STREAM,
      LATERAL FLATTEN(INPUT => RECORD_CONTENT, PATH => 'records', OUTER => TRUE) AS f
    WHERE COALESCE(f.value, RECORD_CONTENT) IS NOT NULL
  );

-- Resume the task (tasks are suspended by default)
ALTER TASK FLATTEN_FLOW_TASK RESUME;

-- -----------------------------------------------------------------------------
-- 6. Stream on FLOW_FEATURES for Inference Task Consumption
-- -----------------------------------------------------------------------------
CREATE OR REPLACE STREAM FLOW_FEATURES_STREAM
  ON TABLE FLOW_FEATURES
  APPEND_ONLY = TRUE
  COMMENT = 'CDC stream for unprocessed flow features (consumed by INFERENCE_TASK)';

-- Note: INFERENCE_TASK is created in 03_snowpark_integration.sql
-- after the SPROC SP_RUN_NIDS_INFERENCE is registered.

-- =============================================================================
-- Deployment Notes (Phase 1):
-- =============================================================================
-- 1. Create S3 bucket for flow logs (e.g., froststream-nids-flows-<account>-<region>)
-- 2. Create IAM user 'froststream_ingest' (programmatic) with S3 read-only on the
--    bucket and its objects (s3:ListBucket, s3:GetObject, s3:GetBucketLocation)
-- 3. Store its keys as AWS_INGEST_ACCESS_KEY_ID / AWS_INGEST_SECRET_ACCESS_KEY in .env
-- 4. Configure S3 Event Notification: s3:ObjectCreated:* -> pipe's SQS queue
--    (tools/provision_aws.py --notify-only)
-- 5. Create Snowpipe auto-ingest: ALTER PIPE PIPE_RAW_FLOW SET PIPE_EXECUTION_PAUSED = FALSE;
-- 6. Verify: SELECT * FROM TABLE(INFORMATION_SCHEMA.COPY_HISTORY(TABLE_NAME=>'RAW_FLOW_LANDING'));
-- =============================================================================