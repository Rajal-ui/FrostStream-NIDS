# FrostStream NIDS Testing, Running, AWS, and Snowflake Guide

## Purpose and safety

This guide takes an operator or developer from local setup to a controlled cloud verification. It documents the commands present in this repository and the manual prerequisites around them.

Read these rules before using the cloud path:

- Start with `EXECUTION_MODE=LOCAL` and a disposable dataset.
- Use a non-production AWS account or an explicitly approved sandbox for infrastructure tests.
- Do not run live packet capture on a network you do not own or are authorized to monitor.
- Do not commit `.env`, private keys, passwords, access keys, or raw captures.
- Keep `SOAR_DISPATCH_TASK` suspended until the API Gateway/Lambda path has been reviewed and tested.
- A NACL deny rule can interrupt legitimate traffic. Confirm the target NACL, rule range, and rollback procedure first.
- This guide documents commands; it does not grant AWS, Snowflake, or network permissions.

## 1. Prerequisites

### Local

- Python 3.10 or later.
- PowerShell 7 (`pwsh`) or another supported shell.
- Sufficient disk space for a virtual environment, pip packages, model artifacts, and captures.
- Npcap or another supported packet-capture driver only for live Scapy sniffing. PCAP replay does not require live-capture permissions.

### Cloud

- An AWS account and region with permission to manage the resources used by the selected deployment.
- A Snowflake account with permission to create or use the target database, schema, warehouses, stages, streams, tasks, pipes, procedures, and integrations.
- An S3 landing bucket and a Kinesis Data Firehose delivery stream whose S3 destination uses the `flows/` prefix.
- A Snowflake connection method: environment variables, a Snowflake CLI profile, or another approved secret store.
- AWS SAM CLI if deploying the optional SOAR stack from `infra/template.yaml`.

Install and verify the common tools:

```powershell
python --version
git --version
aws --version
sam --version
snow --version
```

`snow` is optional when using the Python deployment helper. The PowerShell deployment scripts require it.

## 2. Local installation

Run all commands from the repository root.

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

The `.env` file is a template and is ignored by Git. Cloud deployment helpers such as `deploy_cloud.py` and `provision_aws.py` load it; local commands do not automatically load it. Set local values explicitly in the current process when needed:

```powershell
$env:EXECUTION_MODE = "LOCAL"
$env:LOCAL_MODEL_DIR = "storage/models"
$env:LOCAL_FLOW_OUTPUT = "storage/captured_flows.jsonl"
$env:LOCAL_ALERT_DB = "storage/alerts.db"
$env:CONFIDENCE_THRESHOLD = "0.90"
$env:CRITICAL_CONFIDENCE_THRESHOLD = "0.95"
$env:ANOMALY_THRESHOLD = "-0.2"
$env:PSI_DRIFT_THRESHOLD = "0.25"
```

The local output path is a JSON-lines file despite the historical `.csv` name in some defaults. The sink writes one JSON object per line. The training, inference, and drift commands use their `--out-dir`/`--model-dir` options for model paths; the current inference CLI writes alert rows to `storage/alerts.db` unless logging is disabled.

## 3. Run the automated tests

Run the complete suite:

```powershell
python -m pytest tests/ -v
```

Useful focused commands:

```powershell
python -m pytest tests/test_flow_processor.py -v
python -m pytest tests/test_execution_mode.py -v
python -m pytest tests/test_soar_mitigator.py -v
python -m pytest tests/test_e2e_real_capture.py -v
python -m pytest tests/test_models.py -v
```

**Current baseline: 82 passing tests** (as of 2026-09-26). Treat this as a repository baseline, not a guarantee that an external AWS or Snowflake account is configured correctly.

A quick offline import check is also useful:

```powershell
python -m compileall -q src ingestion tests tools
```

## 4. Train and run the local model

### 4.1 Train artifacts

```powershell
$env:EXECUTION_MODE = "LOCAL"
python -m src.models.train --out-dir storage/models --samples 8000
```

Expected local artifacts are under `storage/models/`:

```text
ensemble_classifier.joblib
isolation_forest.joblib
preprocessor.joblib
baseline_distribution.json
manifest.json
```

Read `manifest.json` to review the model version, class names, and measured training/test metrics. Do not treat synthetic sample metrics as production performance.

### 4.2 Replay generated packets

This command exercises packet aggregation without requiring a capture driver:

```powershell
$env:EXECUTION_MODE = "LOCAL"
python -m ingestion.flow_processor --replay-sample --flows 20 --mode LOCAL
```

Inspect the configured `LOCAL_FLOW_OUTPUT`. Each line should contain identifiers and the model feature fields. The output is a test dataset, not proof of live traffic.

### 4.3 Replay a PCAP

```powershell
python -m ingestion.flow_processor --replay "D:\path\to\capture.pcap" --mode LOCAL --out "D:\path\to\replayed_flows.jsonl"
```

The replay path needs permission to read the file and the installed Python dependencies. It does not send traffic to the network.

### 4.4 Capture a live interface

Use an interface name supported by Scapy. On Windows, the interface may be a name or Npcap GUID:

```powershell
$env:SCAPY_INTERFACE = "<approved-interface>"
python -m ingestion.flow_processor --sniff --duration 30 --mode LOCAL
```

You can pass the interface directly:

```powershell
python -m ingestion.flow_processor --sniff "<approved-interface>" --duration 30 --mode LOCAL
```

If capture fails, check the interface name, Npcap installation, process permissions, and whether the selected interface carries the traffic you intend to test.

### 4.5 Score local flows

Score a generated sample or a CSV:

```powershell
python -m src.models.inference --model-dir storage/models
python -m src.models.inference --flows "D:\path\to\flows.csv" --model-dir storage/models
```

The command prints a summary such as `scored=... alerts_raised=... critical=...`. The current CLI writes alert rows to `storage/alerts.db` unless `--no-log` is used.

### 4.6 Run local drift monitoring

```powershell
python -m src.models.drift_monitor --model-dir storage/models
python -m src.models.drift_monitor --model-dir storage/models --perturb 0.10
```

The first command compares generated data with the saved baseline. The second deliberately perturbs a portion of TCP/HTTP values to exercise the reporting path. A local report is written to `storage/models/drift_report.json`.

## 5. Launch the local dashboard

After training artifacts exist, run:

```powershell
streamlit run app.py
```

The usual local URL is `http://localhost:8501`. The dashboard is an analyst interface; it is not a replacement for the SQL verification queries in this guide.

For cloud reporting, prefer the Snowflake `LIVE_*` views. The current dashboard source may query base tables directly, so verify which tables a displayed metric uses before treating it as a live-only metric.

## 6. Cloud configuration

### 6.1 Required environment groups

Set deployment values in the current shell or use a secret manager. Do not paste real values into a shared terminal transcript.

Snowflake:

```powershell
$env:SNOWFLAKE_ACCOUNT = "<account-identifier>"
$env:SNOWFLAKE_USER = "<deployment-user>"
$env:SNOWFLAKE_PASSWORD = "<use-a-secret-store>"
$env:SNOWFLAKE_ROLE = "<deployment-role>"
$env:SNOWFLAKE_DATABASE = "FROSTSTREAM_NIDS"
$env:SNOWFLAKE_SCHEMA = "CORE"
$env:SNOWFLAKE_WAREHOUSE = "NIDS_ANALYTICS_WH"
```

For key-pair authentication, the cloud deployment helper supports `SNOWFLAKE_PRIVATE_KEY_PATH` and, when needed, `SNOWFLAKE_PRIVATE_KEY_PASSPHRASE`; use the account-approved Snowpark authentication method for procedures and other Snowpark clients.

AWS:

```powershell
$env:AWS_ACCESS_KEY_ID = "<use-an-approved-credential-chain>"
$env:AWS_SECRET_ACCESS_KEY = "<use-an-approved-credential-chain>"
$env:AWS_DEFAULT_REGION = "<region>"
$env:AWS_ACCOUNT_ID = "<12-digit-account-id>"
$env:S3_FLOW_BUCKET = "<unique-landing-bucket>"
$env:FIREHOSE_DELIVERY_STREAM_NAME = "<firehose-delivery-stream>"
```

SOAR values are required only for the response path:

```powershell
$env:TARGET_VPC_ID = "<vpc-id>"
$env:TARGET_NACL_ID = "<nacl-id>"
$env:NACL_RULE_START = "100"
$env:NACL_RULE_END = "199"
$env:BLOCK_TTL_HOURS = "24"
```

The dedicated Snowflake ingest user path additionally needs:

```powershell
$env:AWS_INGEST_ACCESS_KEY_ID = "<low-privilege-ingest-key>"
$env:AWS_INGEST_SECRET_ACCESS_KEY = "<low-privilege-ingest-secret>"
```

### 6.2 Confirm AWS identity and Snowflake connectivity

```powershell
aws sts get-caller-identity
python tools/deploy_cloud.py --check
```

`deploy_cloud.py --check` reads the repository `.env` when present, creates a Snowpark session, and prints account/session context without printing configured secrets. It does not verify Firehose or S3.

## 7. Provision the AWS/Snowflake ingestion boundary

There are two supported authentication choices. Choose one and do not mix trust policies accidentally.

### Option A — Role-based storage integration

Use this when the Snowflake integration and cross-account `AssumeRole` trust are approved. The intended sequence is:

1. Create or approve `S3_FLOW_INTEGRATION` in Snowflake.
2. Read its `STORAGE_AWS_IAM_USER_ARN` and `STORAGE_AWS_EXTERNAL_ID` from `DESCRIBE INTEGRATION`.
3. Ensure the S3 stage uses the integration and the `flows/` prefix.
4. Run `python tools/provision_aws.py` to reconcile the IAM role, bucket, and notification.
5. Run `python tools/check_ingest.py` to compare the Snowflake trust values and list the stage.

The current `02_snowpipe.sql` has the role-based stage definition commented and defaults to the credential-based stage. An operator must intentionally create/recreate the integration-based stage before using Option A. Do not assume that running the default migration selects the role path.

The helper expects the integration to exist before its default role-based run:

```powershell
python tools/provision_aws.py
python tools/check_ingest.py
```

`check_ingest.py` is for the role-integration path. It is not a valid check for an access-key-only stage.

### Option B — Dedicated ingest IAM user

This is the default documented SQL path when cross-account role assumption is unavailable. The helper can create or reuse `froststream_ingest` with read-only access to `s3://<bucket>/flows/*` and persist newly created keys to `.env`:

```powershell
python tools/provision_aws.py --ingest-user
python tools/provision_aws.py --notify-only
```

`--notify-only` creates/checks the bucket and connects the S3 `ObjectCreated` notification for the `flows/` prefix to the Snowpipe SQS channel. The keys are sensitive; do not print or commit `.env`.

### 7.1 Firehose prerequisite

The Python repository does not create the Firehose delivery stream. Before sending cloud flow records, ensure that:

- the stream exists in the selected region;
- its S3 destination is the configured landing bucket;
- the destination prefix is `flows/`;
- the Firehose execution role can write to that prefix;
- buffering and retry behavior has been reviewed for the expected volume.

A non-production test can be sent through the cloud sink after these prerequisites are met:

```powershell
$env:EXECUTION_MODE = "CLOUD"
python -m ingestion.flow_processor --replay-sample --flows 20 --mode CLOUD
```

This is a functional transport test, not evidence of real traffic. Use the provenance and synthetic markers when reviewing the resulting rows.

## 8. Deploy Snowflake phase 1

### 8.1 Python helper

The helper executes the foundation DDL, Snowpipe SQL, and verification SQL statement-by-statement:

```powershell
python tools/deploy_cloud.py --phase 1
```

For the access-key-only stage, use `--skip-verify` if the verification file attempts to describe an integration that intentionally does not exist, then run targeted checks below:

```powershell
python tools/deploy_cloud.py --phase 1 --skip-verify
python tools/check_pipeline.py
```

For the role-based integration path:

```powershell
python tools/deploy_cloud.py --phase 1
python tools/check_ingest.py
python tools/check_pipeline.py
```

### 8.2 Snowflake CLI alternative

If `snow` is installed and a connection profile exists:

```powershell
snow sql -f snowflake_setup/01_tables.sql
snow sql -f snowflake_setup/02_snowpipe.sql
snow sql -f snowflake_setup/verify_phase1.sql
```

The PowerShell wrapper is:

```powershell
pwsh ./snowflake_setup/deploy_phase1.ps1
pwsh ./snowflake_setup/deploy_phase1.ps1 -SkipVerify
```

For Option B, the wrapper can run the DDL with `-SkipVerify`, but its follow-up checklist describes the historical role-based integration path. Follow the Option B sequence above and do not run `check_ingest.py` or the integration portion of `verify_phase1.sql` unless `S3_FLOW_INTEGRATION` exists. Run migrations in a controlled order. The SQL creates or replaces named Snowflake objects in the configured `CORE` schema; review the target account before running it.

## 9. Package and register Snowpark code

Build the archive offline first:

```powershell
python tools/deploy_snowpark_code.py --build
```

The archive should be `.cache/snowpark_code.zip` and contain the `src/` and `data/` package trees. Upload and register procedures/tasks with:

```powershell
python tools/deploy_cloud.py --phase 3
```

`deploy_cloud.py --phase 3` packages/uploads the code, runs `03_snowpark_integration.sql` without SOAR blocks by default, and runs Phase 3 verification. This is the safer first cloud orchestration deployment.

The Snowflake CLI wrapper is:

```powershell
pwsh ./snowflake_setup/deploy_phase3.ps1
```

The wrapper runs the full SQL file, including its SOAR section, and does not perform the Python helper's environment-token substitution. Do not use that form until the API placeholders and AWS trust relationship are ready and the SQL has been rendered for the target account. A Python-only build can be useful before credentials are available:

```powershell
python tools/deploy_snowpark_code.py --build
```

## 10. Train and register cloud model artifacts

The training module reads Snowflake connection values from the process environment. Set them through your approved secret mechanism, then run:

```powershell
$env:EXECUTION_MODE = "CLOUD"
python -m src.models.train --mode CLOUD --out-dir storage/models --samples 8000
```

The command should:

1. train the ensemble and anomaly detector;
2. write local artifacts;
3. upload the four required files to `@CORE.MODEL_STAGE`;
4. insert four versioned rows into `CORE.MODEL_REGISTRY`.

Verify the stage in Snowsight or with Snowflake CLI:

```sql
USE DATABASE FROSTSTREAM_NIDS;
USE SCHEMA CORE;
LIST @CORE.MODEL_STAGE;
SELECT MODEL_NAME, VERSION, MODEL_TYPE, IS_ACTIVE
FROM MODEL_REGISTRY
ORDER BY REGISTERED_AT DESC;
```

Do not run inference procedures until the required model files and code archive are present.

## 11. Verify Snowflake ingestion and processing

### 11.1 Pipe and stage

```powershell
python tools/check_pipeline.py
```

Equivalent SQL checks:

```sql
USE DATABASE FROSTSTREAM_NIDS;
USE SCHEMA CORE;

SHOW PIPES LIKE 'PIPE_RAW_FLOW';
SELECT SYSTEM$PIPE_STATUS('CORE.PIPE_RAW_FLOW');
SHOW STREAMS IN SCHEMA CORE;
SHOW TASKS IN SCHEMA CORE;
LIST @CORE.S3_FLOW_STAGE;
```

For a healthy auto-ingest pipe, inspect `executionState`, pending file count, and Snowflake copy history. A pipe can exist while its S3 notification is not connected, so object arrival must also be checked.

### 11.2 End-to-end smoke ingest

The smoke helper uploads a sample file under a `flows/smoke_...` name, then polls Snowflake for raw and flattened rows:

```powershell
python tools/smoke_ingest.py --wait 180
```

The helper is designed to pass when at least two feature rows have appeared. It is a transport and flattening test. The `smoke_` filename is used by the flatten task to mark rows as synthetic for audit purposes.

After it completes, inspect:

```sql
SELECT COUNT(*) AS RAW_ROWS FROM RAW_FLOW_LANDING;
SELECT COUNT(*) AS FEATURE_ROWS FROM FLOW_FEATURES;
SELECT IS_SYNTHETIC, COUNT(*) AS ROW_COUNT
FROM FLOW_FEATURES
GROUP BY IS_SYNTHETIC
ORDER BY IS_SYNTHETIC;
SELECT FILE_NAME, FILE_ROW_NUMBER, INGESTION_TIMESTAMP
FROM RAW_FLOW_LANDING
ORDER BY INGESTION_TIMESTAMP DESC
LIMIT 10;
```

### 11.3 Procedure smoke tests

Run the procedures manually after model files are staged:

```sql
CALL CORE.SP_RUN_NIDS_INFERENCE();
CALL CORE.SP_RUN_DRIFT_MONITOR();
```

The inference procedure returns a string containing scored, alert, critical, and processed counts. A `scored=0` result can mean there are no unprocessed rows; it is not automatically a failure.

Check processed state and alerts:

```sql
SELECT PROCESSED_FLAG, COUNT(*) AS ROW_COUNT
FROM FLOW_FEATURES
GROUP BY PROCESSED_FLAG;

SELECT SEVERITY, ATTACK_TYPE, MITIGATION_STATUS, COUNT(*) AS ROW_COUNT
FROM NIDS_ALERTS
GROUP BY SEVERITY, ATTACK_TYPE, MITIGATION_STATUS
ORDER BY SEVERITY, ATTACK_TYPE;
```

## 12. Verify live-only views and synthetic provenance

Operational reporting should use the live views:

```sql
SELECT COUNT(*) AS LIVE_FLOW_ROWS
FROM CORE.LIVE_FLOW_FEATURES;

SELECT COUNT(*) AS LIVE_ALERT_ROWS
FROM CORE.LIVE_NIDS_ALERTS;

SELECT SEVERITY, COUNT(*) AS LIVE_ALERTS
FROM CORE.LIVE_NIDS_ALERTS
GROUP BY SEVERITY
ORDER BY SEVERITY;

SELECT ALERT_ID, FLOW_ID, SRC_IP, DST_IP, ATTACK_TYPE,
       CONFIDENCE, SEVERITY, IS_ZERO_DAY_SUSPECT,
       IS_SYNTHETIC, MITIGATION_STATUS, TIMESTAMP
FROM CORE.LIVE_NIDS_ALERTS
ORDER BY TIMESTAMP DESC
LIMIT 50;
```

The base tables are intentionally available for audit and debugging. Do not assume a query against a base table excludes smoke or synthetic rows.

A useful provenance check is to inspect the landing metadata and the feature marker separately:

```sql
SELECT FILE_NAME, FILE_ROW_NUMBER, INGESTION_TIMESTAMP
FROM CORE.RAW_FLOW_LANDING
ORDER BY INGESTION_TIMESTAMP DESC
LIMIT 100;

SELECT FLOW_ID, IS_SYNTHETIC, CREATED_AT
FROM CORE.FLOW_FEATURES
ORDER BY CREATED_AT DESC
LIMIT 100;
```

The smoke-file convention is a repository convention, not a universal data-quality guarantee. Approved external producers should preserve provenance in their own naming/metadata process.

## 13. Verify model stage, procedures, and tasks

```sql
LIST @CORE.SNOWPARK_CODE_STAGE;
LIST @CORE.MODEL_STAGE;
SHOW PROCEDURES IN SCHEMA CORE;
DESCRIBE PROCEDURE CORE.SP_RUN_NIDS_INFERENCE();
DESCRIBE PROCEDURE CORE.SP_RUN_DRIFT_MONITOR();
SHOW TASKS IN SCHEMA CORE;
```

Expected initial state:

- `SP_RUN_NIDS_INFERENCE` and `SP_RUN_DRIFT_MONITOR` exist.
- `FLATTEN_FLOW_TASK`, `INFERENCE_TASK`, and `DRIFT_MONITOR_TASK` are resumed.
- `SOAR_DISPATCH_TASK` is suspended until explicitly approved and ready.

Check task history using the Snowflake account's supported task-history syntax. The important evidence is a recent successful run or a specific error message; do not rely only on the task definition.

## 14. Verify drift monitoring

```sql
SELECT REPORT_ID, CHECK_TIMESTAMP, MAX_PSI, STATUS
FROM CORE.DRIFT_REPORTS
ORDER BY CHECK_TIMESTAMP DESC
LIMIT 20;

SELECT *
FROM TABLE(
  FLATTEN(INPUT => DRIFTED_FEATURES)
)
ORDER BY 1;
```

Review the PSI threshold and the feature details. A drift alert is a signal to investigate data quality, traffic mix, sensor changes, or model relevance. It is not automatically a malicious-traffic conclusion and should not automatically trigger a NACL response.

## 15. Optional SOAR deployment

### 15.1 Safety gate

Before deploying the response stack, record:

- target VPC and NACL IDs;
- the managed rule-number range;
- the rollback owner;
- a test source address and expected cleanup time;
- the Snowflake API integration principal and external ID;
- the IAM role that Snowflake will assume;
- the approval to create network changes.

### 15.2 Inspect the SAM template

`infra/template.yaml` creates:

- API Gateway REST API with AWS IAM authorization;
- mitigator Lambda;
- cleanup Lambda on an hourly EventBridge schedule;
- `SnowflakeSOARFunctionRole` for API invocation;
- environment variables for NACL and Snowflake write-back settings.

Build the template without changing the account:

```powershell
sam build --template-file infra/template.yaml
```

Deploy only with reviewed parameters:

```powershell
sam deploy --guided --template-file infra/template.yaml
```

The guided deployment requires values including the target NACL, target VPC, Snowflake API principal/external ID, and Snowflake write-back settings. The template contains a password parameter; use a secure deployment process and do not place a real password in a shell transcript or a committed parameter file.

The stack output `MitigatorApiUrl` is the URL needed in the Snowflake external function configuration. The API ID and region placeholders in `03_snowpark_integration.sql` must be replaced before SOAR SQL is enabled.

### 15.3 Enable Snowflake SOAR integration

Only after the stack and trust policy are verified:

```powershell
python tools/deploy_cloud.py --phase 3 --enable-soar
```

This substitutes the configured AWS account, region, and API ID where possible and includes the SOAR DDL. Inspect the generated SQL and the API integration before running it. Then verify:

```sql
SHOW API INTEGRATIONS LIKE 'SOAR_API_INTEGRATION';
SHOW EXTERNAL FUNCTIONS IN SCHEMA CORE;
DESCRIBE FUNCTION CORE.EXTERNAL_MITIGATE_IP(VARCHAR, VARCHAR, FLOAT, VARCHAR);
SHOW TASKS LIKE 'SOAR_DISPATCH_TASK' IN SCHEMA CORE;
```

The dispatch task filters for:

- `SEVERITY IN ('CRITICAL', 'HIGH')`;
- confidence greater than `0.95`;
- `MITIGATION_STATUS = 'PENDING'`;
- `IS_SYNTHETIC = FALSE`.

Test the endpoint using an approved payload and a non-production target. A successful new block returns `ACTIONED`; a duplicate source returns `SUPPRESSED`; invalid input or an AWS error returns `FAILED`.

### 15.4 Cleanup and expiry

The cleanup Lambda is scheduled hourly. It reads `FrostStream_TTL_<ip>` tags, compares expiry epochs with UTC, deletes expired NACL entries, removes the tags, and attempts to mark matching `ACTIONED` alerts `EXPIRED`.

Verify the rule and tag without changing it:

```powershell
aws ec2 describe-network-acls --network-acl-ids "<nacl-id>" --region "<region>"
```

Do not delete a rule manually without recording its rule number, source `/32`, tag, and alert. Natural expiry verification should be performed only after the configured TTL has elapsed and the target is approved for the test.

## 16. Monitoring checklist

### AWS

- Firehose delivery stream is `ACTIVE` and has no growing delivery failures.
- S3 objects appear under the expected `flows/` prefix.
- S3 event notifications are enabled for the Snowpipe SQS channel.
- API Gateway returns successful responses for approved requests and rejects unauthorized requests.
- Mitigator Lambda errors, timeouts, and throttles remain within the operating threshold.
- Cleanup Lambda runs hourly and reports expired addresses.
- NACL rule usage remains inside the approved range.

Useful read-only checks include:

```powershell
aws firehose describe-delivery-stream --delivery-stream-name "<stream>" --region "<region>"
aws s3api list-objects-v2 --bucket "<bucket>" --prefix "flows/" --region "<region>"
aws lambda get-function-configuration --function-name "<function>" --region "<region>"
```

### Snowflake

- Pipe execution state and copy history show expected files.
- `FLATTEN_FLOW_TASK` and `INFERENCE_TASK` have recent successful runs.
- `FLOW_FEATURES.PROCESSED_FLAG` does not grow unexpectedly.
- Model/code stages contain the expected versioned files.
- `DRIFT_REPORTS` is current and reviewed.
- `LIVE_*` views contain only non-synthetic rows.
- SOAR task state and `MITIGATION_STATUS` values are audited.

Useful SQL:

```sql
SELECT SYSTEM$PIPE_STATUS('CORE.PIPE_RAW_FLOW');

SELECT *
FROM TABLE(INFORMATION_SCHEMA.COPY_HISTORY(TABLE_NAME => 'RAW_FLOW_LANDING'))
ORDER BY LAST_COMMIT_TIMESTAMP DESC
LIMIT 20;

SELECT PROCESSED_FLAG, COUNT(*) AS ROW_COUNT
FROM CORE.FLOW_FEATURES
GROUP BY PROCESSED_FLAG;

SELECT SEVERITY, MITIGATION_STATUS, COUNT(*) AS ROW_COUNT
FROM CORE.LIVE_NIDS_ALERTS
GROUP BY SEVERITY, MITIGATION_STATUS;
```

## 17. Troubleshooting

| Symptom | Likely cause | Checks and safe action |
| --- | --- | --- |
| `No interface specified` | `SCAPY_INTERFACE` is empty and `--sniff` has no argument | Pass an approved interface or set `SCAPY_INTERFACE`. |
| Scapy cannot read a PCAP | Missing dependency, bad path, or permissions | Run `python -m pip install -r requirements.txt`; verify the path and read permission. |
| `CLOUD FlowSink requires FIREHOSE_DELIVERY_STREAM_NAME` | Stream variable is absent | Set the exact Firehose delivery stream name and confirm the stream exists. |
| Snowflake connection fails | Missing account/user/authentication or wrong role | Run `python tools/deploy_cloud.py --check`; inspect the safe error output. |
| `S3_FLOW_INTEGRATION` is missing | Option B access-key stage was selected | Use the Option B checks; do not force the role verification helper. |
| Firehose has data but Snowpipe does not | S3 event/SQS notification or prefix mismatch | Compare Firehose destination, stage URL, `flows/`, and `SHOW PIPES` notification channel. |
| Raw rows exist but feature rows do not | Flatten task suspended, stream has no data, or parse error | Check `FLATTEN_FLOW_TASK`, `RAW_FLOW_STREAM`, task history, and `RAW_FLOW_LANDING.RECORD_CONTENT`. |
| Features exist but inference fails | Missing model/code stage or incompatible version | `LIST` both stages and run the verification SQL before calling the procedure. |
| Alerts are created but not actioned | SOAR task suspended, confidence/severity does not qualify, or API failure | Inspect task state, API integration, Lambda logs, and alert fields. Do not resume blindly. |
| NACL rule already exists | Idempotency guard is working | Inspect the existing `/32` and alert response; do not create a duplicate rule. |
| Drift alert appears | Traffic or data distribution changed | Compare feature PSI, sensor health, traffic mix, and model version before retraining. |
| Dashboard count differs from live SQL | Dashboard may query base tables or different data | Compare the dashboard query with `LIVE_*` views and the task timestamps. |
| Cleanup does not remove a rule | TTL has not elapsed, tag is malformed, or permissions are missing | Inspect the NACL tags and cleanup Lambda logs; do not delete a rule without change control. |

## 18. Safe pause, rollback, and maintenance

Before maintenance that can affect scoring or response:

```sql
ALTER TASK CORE.SOAR_DISPATCH_TASK SUSPEND;
ALTER TASK CORE.INFERENCE_TASK SUSPEND;
ALTER TASK CORE.FLATTEN_FLOW_TASK SUSPEND;
ALTER PIPE CORE.PIPE_RAW_FLOW SET PIPE_EXECUTION_PAUSED = TRUE;
```

After maintenance, resume only the components that were intentionally changed:

```sql
ALTER PIPE CORE.PIPE_RAW_FLOW SET PIPE_EXECUTION_PAUSED = FALSE;
ALTER TASK CORE.FLATTEN_FLOW_TASK RESUME;
ALTER TASK CORE.INFERENCE_TASK RESUME;
```

Resume SOAR separately only after the response path has been checked:

```sql
ALTER TASK CORE.SOAR_DISPATCH_TASK RESUME;
```

For a bad model release, preserve the old version, stage the replacement, validate it, and update active model metadata through an approved process. Do not delete an artifact while a task may still need it.

## 19. Evidence checklist

A cloud verification packet should include, without secrets:

- repository revision and model version;
- Python package versions;
- AWS region and non-secret resource identifiers;
- Snowflake database/schema/warehouse names;
- Firehose and pipe state;
- S3/SQS event wiring confirmation;
- smoke-ingest command result;
- raw, feature, and alert row counts;
- live-view and synthetic-provenance queries;
- inference and drift procedure results;
- API/Lambda/NACL test result if SOAR was tested;
- screenshots or exported query results with sensitive values redacted;
- task and model rollback plan.

## 20. Quick command reference

```powershell
# Local
python -m pytest tests/ -v
python -m src.models.train --out-dir storage/models --samples 8000
python -m ingestion.flow_processor --replay-sample --flows 20 --mode LOCAL
python -m src.models.inference --model-dir storage/models
python -m src.models.drift_monitor --model-dir storage/models
streamlit run app.py

# Cloud checks
python tools/deploy_cloud.py --check
python tools/provision_aws.py --ingest-user
python tools/provision_aws.py --notify-only
python tools/deploy_cloud.py --phase 1
python tools/deploy_snowpark_code.py --build
python tools/deploy_cloud.py --phase 3
python tools/smoke_ingest.py --wait 180
python tools/check_pipeline.py

# Optional SOAR
sam build --template-file infra/template.yaml
sam deploy --guided --template-file infra/template.yaml
python tools/deploy_cloud.py --phase 3 --enable-soar
```

## 21. Related documents

- `README.md` — concise project overview and quick start.
- `PROJECT_DOCUMENTATION.md` — technical handbook and component reference.
- `docs/NIDS-SecOps Project Master Document.md` — public scope, architecture, governance, and roadmap.
- `snowflake_setup/verify_phase1.sql` — foundation and ingestion checks.
- `snowflake_setup/verify_phase3.sql` — procedure, stage, stream, and task checks.
- `.env.example` — environment variable template.

## 22. AWS Console navigation guide

This section tells you exactly what to search for in the AWS Console, where to navigate, and what to verify at each step.

### 22.1 Kinesis Data Firehose
**Search**: "Kinesis Data Firehose" → "Delivery streams"
**Select**: Your stream (e.g., `froststream-flows`)
**Verify**:
- **Status**: `ACTIVE`
- **Destination**: `Amazon S3` → bucket name matches `$env:S3_FLOW_BUCKET`
- **S3 prefix**: `flows/`
- **IAM role**: Click role ARN → verify permissions include `s3:PutObject`, `s3:AbortMultipartUpload` on `arn:aws:s3:::<bucket>/flows/*`
- **Monitoring tab**: `IncomingRecords` > 0, `DeliveryToS3.Success` > 0, `DeliveryToS3.Failed` = 0

### 22.2 S3 Landing Bucket
**Search**: "S3" → Buckets → `<your-bucket>`
**Navigate**: Objects → `flows/` prefix
**Verify**:
- Recent objects under `flows/` (timestamp within last run)
- Object format: JSON Lines (download one → open → each line is a valid JSON object)
- **Properties** → **Event notifications**: One notification for `All object create events` → Destination: **SQS Queue** → ARN matches Snowpipe's notification channel (see `SYSTEM$PIPE_STATUS` output)

### 22.3 SQS (Snowpipe Auto-ingest Queue)
**Search**: "SQS" → Queues
**Find**: Queue with name containing `sf-snowpipe-` or similar (created by Snowpipe)
**Verify**:
- **Messages available** > 0 when Firehose delivers
- **Dead-letter queue** configured (optional but recommended)
- **Access policy**: Allows `sqs:SendMessage` from S3 bucket principal

### 22.4 IAM Roles & Policies
**Search**: "IAM" → Roles
**Role-based (Option A)**: `SnowflakeFlowLogsRole`
- **Trust relationships**: `Principal.Service: snowflake.amazonaws.com` + `Condition: sts:ExternalId` matches `DESCRIBE INTEGRATION` output
- **Permissions**: Inline policy allowing `s3:GetObject`, `s3:ListBucket` on `arn:aws:s3:::<bucket>/flows/*`
**Access-key (Option B)**: `froststream_ingest` user
- **Permissions**: `AmazonS3ReadOnlyAccess` or custom policy for `s3:GetObject` on `flows/*`
- **Access keys**: Created, stored in `.env` as `AWS_INGEST_ACCESS_KEY_ID` / `AWS_INGEST_SECRET_ACCESS_KEY`

### 22.5 Lambda Functions (SOAR)
**Search**: "Lambda" → Functions
**Mitigator** (e.g., `FrostStreamMitigator`):
- **Configuration** → **Environment variables**: `TARGET_VPC_ID`, `TARGET_NACL_ID`, `NACL_RULE_START`, `NACL_RULE_END`, `BLOCK_TTL_HOURS`, Snowflake creds
- **Permissions**: Execution role has `ec2:CreateNetworkAclEntry`, `ec2:DeleteNetworkAclEntry`, `ec2:DescribeNetworkAcls`, `ec2:ReplaceNetworkAclEntry`, `ec2:CreateTags`, `ec2:DeleteTags` on target NACL
- **Monitoring**: Invocations, Errors, Duration, Throttles
- **Logs**: CloudWatch Log Group `/aws/lambda/FrostStreamMitigator` → filter `ACTIONED`, `SUPPRESSED`, `FAILED`

**Cleanup** (e.g., `FrostStreamCleanup`):
- **Triggers**: EventBridge rule (schedule `rate(1 hour)`)
- **Environment variables**: Same NACL vars + Snowflake write-back creds
- **Logs**: Filter `EXPIRED`, `deleted`, `tag`

### 22.6 API Gateway (REST)
**Search**: "API Gateway" → REST APIs
**Select**: `FrostStreamMitigatorApi` (or stack-named)
**Verify**:
- **Resources** → `/mitigate` → **POST** → **Method Request** → **Authorization**: `AWS_IAM`
- **Stages** → `prod` → **Invoke URL** (e.g., `https://<api-id>.execute-api.<region>.amazonaws.com/prod/mitigate`) → copy for Snowflake external function
- **Logs**: CloudWatch → API Gateway execution logs → check 4xx/5xx

### 22.7 EventBridge (Cleanup Schedule)
**Search**: "EventBridge" → Rules
**Find**: Rule targeting `FrostStreamCleanup` Lambda
**Verify**: Schedule expression `rate(1 hour)`, State `ENABLED`

### 22.8 NACL (Network ACL)
**Search**: "VPC" → Network ACLs → `<target-nacl-id>`
**Verify**:
- **Inbound rules**: Rules in range `NACL_RULE_START`–`NACL_RULE_END` (default 100–199)
- **Rule entries**: `CidrBlock: <ip>/32`, `Rule Action: DENY`, `Tag: FrostStream_TTL_<ip>=<epoch>`
- **No conflicts**: Lower rule numbers not already denying same CIDR

### 22.9 CloudWatch Logs (Unified Search)
**Search**: "CloudWatch" → Log groups
**Filter patterns**:
- `/aws/lambda/FrostStreamMitigator` → `ACTIONED`, `SUPPRESSED`, `FAILED`
- `/aws/lambda/FrostStreamCleanup` → `EXPIRED`, `deleted`
- `/aws/apigateway/<api-id>` → 4xx, 5xx, latency

---

## 23. Snowflake UI (Snowsight) navigation guide

This section tells you where to click in Snowsight (Snowflake's web UI) to verify each component.

### 23.1 Database & Schema Context
**Top bar**: Select Role → `ACCOUNTADMIN` or deployment role → **Warehouse** → `NIDS_INGEST_WH` or `NIDS_ANALYTICS_WH` → **Database** → `FROSTSTREAM_NIDS` → **Schema** → `CORE`

### 23.2 Tables & Data Preview
**Left nav**: Data → Databases → `FROSTSTREAM_NIDS` → `CORE` → Tables
| Table | What to check |
| --- | --- |
| `RAW_FLOW_LANDING` | Row count, `FILE_NAME` values (should include `smoke_...`), `INGESTION_TIMESTAMP` recent |
| `FLOW_FEATURES` | Row count, `IS_SYNTHETIC` distribution, `PROCESSED_FLAG` (should be mostly TRUE after inference), `CREATED_AT` |
| `NIDS_ALERTS` | Row count, `SEVERITY` distribution, `MITIGATION_STATUS` (PENDING/ACTIONED/SUPPRESSED/EXPIRED/FAILED), `IS_SYNTHETIC` = FALSE for live |
| `MODEL_REGISTRY` | 4+ rows, one per artifact type, `IS_ACTIVE` = TRUE for current version |
| `DRIFT_REPORTS` | Recent rows, `STATUS` (OK/WARNING/ALERT), `MAX_PSI` values |

**Action**: Click any table → "Preview Data" (top right) → run ad-hoc queries.

### 23.3 Stages
**Left nav**: Data → Databases → `FROSTSTREAM_NIDS` → `CORE` → Stages
| Stage | What to check |
| --- | --- |
| `S3_FLOW_STAGE` | URL shows `s3://<bucket>/flows/`; `LIST @S3_FLOW_STAGE` shows recent files |
| `MODEL_STAGE` | `LIST @MODEL_STAGE` shows 4 `.joblib` + `baseline_distribution.json` |
| `SNOWPARK_CODE_STAGE` | `LIST @SNOWPARK_CODE_STAGE` shows `snowpark_code.zip` |

### 23.4 Pipes
**Left nav**: Data → Pipes → `PIPE_RAW_FLOW`
**Check**:
- **Status**: `RUNNING`
- **Last refreshed**: Recent timestamp
- **Notification channel**: SQS ARN (matches AWS SQS queue)
- **Action**: Click "Refresh" to force metadata sync

**SQL**: `SELECT SYSTEM$PIPE_STATUS('CORE.PIPE_RAW_FLOW');` → parse JSON for `executionState`, `pendingFileCount`.

### 23.5 Streams
**Left nav**: Data → Streams
**Expected**: `RAW_FLOW_STREAM`, `FLOW_FEATURES_STREAM`, `NIDS_ALERTS_STREAM`
**Check**: Each shows `STALE = FALSE`, `STALE_AFTER` timestamp future.

### 23.6 Tasks
**Left nav**: Data → Tasks
| Task | Expected state | Schedule |
| --- | --- | --- |
| `FLATTEN_FLOW_TASK` | `RESUMED` | Every minute |
| `INFERENCE_TASK` | `RESUMED` | Every minute |
| `DRIFT_MONITOR_TASK` | `RESUMED` | Hourly (minute 0) |
| `SOAR_DISPATCH_TASK` | `SUSPENDED` (until approved) | Every minute |

**Action**: Click task → "Task History" tab → verify recent `SUCCEEDED` runs. For failures, click run → "Error Message".

### 23.7 Procedures & External Functions
**Left nav**: Data → Procedures / External Functions
**Procedures**: `SP_RUN_NIDS_INFERENCE()`, `SP_RUN_DRIFT_MONITOR()` → click → "Call" → run manually for smoke test.
**External Functions**: `EXTERNAL_MITIGATE_IP` → verify `API_INTEGRATION = SOAR_API_INTEGRATION`.

### 23.8 API Integrations
**Left nav**: Admin → Integrations → `SOAR_API_INTEGRATION`
**Verify**: `ENABLED = TRUE`, `ALLOWED_AUTHENTICATION_TYPES = AWS_IAM`, `API_AWS_IAM_ROLE_ARN` matches Lambda execution role ARN.

### 23.9 Warehouses & Query History
**Left nav**: Admin → Warehouses → `NIDS_INGEST_WH`, `NIDS_ANALYTICS_WH` → check "Running queries", "Queued queries".
**Query History** (top bar): Filter by warehouse, user, time → verify task queries executing, no long-running stuck queries.

### 23.10 Live Views (Operational Reporting)
**Left nav**: Data → Views → `LIVE_FLOW_FEATURES`, `LIVE_NIDS_ALERTS`
**Use**: These are the only tables dashboards/reports should query. They exclude `IS_SYNTHETIC = TRUE` rows automatically.

---

## 24. Combined AWS + Snowflake verification checklist

Run after each deployment phase:

| Phase | AWS Console | Snowsight |
| --- | --- | --- |
| **Phase 1 (Ingestion)** | Firehose ACTIVE, S3 `flows/` objects, SQS messages, IAM roles correct | Pipe `RUNNING`, `RAW_FLOW_LANDING` rows, `FLATTEN_FLOW_TASK` resumed, `FLOW_FEATURES` populated |
| **Phase 3 (Code/Models)** | — | Stages populated, Procedures exist, Tasks resumed, `MODEL_REGISTRY` active rows |
| **SOAR** | API Gateway + 2 Lambdas deployed, NACL rules creatable, EventBridge scheduled | API Integration enabled, External Function callable, `SOAR_DISPATCH_TASK` resume → test payload → `ACTIONED` |
| **Ongoing** | Firehose delivery, Lambda errors, NACL rule count | Task history, `LIVE_*` views, Drift `STATUS`, Alert mitigation states |
