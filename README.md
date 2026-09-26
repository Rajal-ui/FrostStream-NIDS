# FrostStream NIDS

FrostStream NIDS is a dual-mode network intrusion detection system (NIDS). It turns network packets or existing flow records into 41 NSL-KDD-compatible features, classifies each flow, records security alerts, and can optionally send a qualifying alert to an AWS Network ACL (NACL) mitigation path.

The project has two deliberately separate operating modes:

- **LOCAL** — Scapy capture or offline replay, local model artifacts, JSONL flow output, and a SQLite alert store. This is the best starting point for development and evaluation.
- **CLOUD** — the flow processor sends records to Kinesis Data Firehose, Snowflake loads them through Snowpipe, Snowpark procedures score and monitor them, and an optional SOAR path can call an API Gateway/Lambda function to create a temporary NACL deny rule.

## What the system detects

The current model maps labeled NSL-KDD attacks to five macro-classes:

| Class | Meaning | Examples from the dataset |
| --- | --- | --- |
| `Normal` | Benign traffic | Ordinary service connections |
| `DoS` | Denial of service | Neptune, Smurf, Teardrop |
| `Probe` | Reconnaissance or scanning | Satan, Nmap, Portsweep |
| `R2L` | Remote-to-local access attempts | FTP write, password guessing |
| `U2R` | User-to-root privilege escalation | Buffer overflow, rootkit |

The primary cloud model is a soft-voting ensemble of XGBoost and Random Forest, with an Isolation Forest used for anomaly/possible-zero-day detection. The repository also contains an older five-algorithm benchmark module at `src/models.py`; it is not the same thing as the current `src/models/train.py` training path.

## Data flow

```text
Packets or flow records
        |
        v
ingestion/flow_processor.py
  FlowFeatureExtractor
  - aggregates bidirectional packets
  - calculates 41 NSL-KDD-compatible features
        |
        +--> LOCAL: JSONL flow output
        |
        +--> CLOUD: Kinesis Data Firehose
                         |
                         v
                 S3 flows/ prefix
                         |
                S3 event -> SQS -> Snowpipe
                         |
                         v
                 RAW_FLOW_LANDING
                         |
                 stream + flatten task
                         |
                         v
                  FLOW_FEATURES
                         |
                 Snowpark inference
                         |
                         v
                    NIDS_ALERTS
                         |
             optional qualifying SOAR dispatch
                         |
             API Gateway -> Lambda -> AWS NACL
```

The current repository implements the Scapy/flow-record producer and the Firehose sink. A separate VPC Flow Logs exporter or other production traffic source must deliver records to Firehose; that adapter is outside this repository.

## Local quick start

Use Python 3.10 or later. From the repository root:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

The cloud deployment helpers load `.env`; the local CLI does not automatically load values from that file. The model commands use their explicit `--out-dir`/`--model-dir` options, while the flow and factory components read the relevant process environment variables:

```powershell
$env:EXECUTION_MODE = "LOCAL"
$env:LOCAL_MODEL_DIR = "storage/models"
$env:LOCAL_FLOW_OUTPUT = "storage/captured_flows.csv"
$env:LOCAL_ALERT_DB = "storage/alerts.db"
```

The current local inference CLI logs alerts to `storage/alerts.db` by default; use the model-directory flags explicitly when artifacts are stored elsewhere. `LOCAL_MODEL_DIR` is used by factory-based consumers, while `LOCAL_ALERT_DB` is used by factory-based local alert sinks.

Train local artifacts, replay a small synthetic sample, and score it:

```powershell
python -m src.models.train --out-dir storage/models --samples 8000
python -m ingestion.flow_processor --replay-sample --flows 20 --mode LOCAL
python -m src.models.inference --model-dir storage/models
```

Replay a packet capture instead of generated packets:

```powershell
python -m ingestion.flow_processor --replay path/to/capture.pcap --mode LOCAL --out storage/replayed_flows.jsonl
```

Live sniffing requires Scapy, a supported capture interface, and the permissions required by the host operating system:

```powershell
python -m ingestion.flow_processor --sniff "<interface>" --duration 30 --mode LOCAL
```

Launch the local Streamlit dashboard after training artifacts exist:

```powershell
streamlit run app.py
```

## Cloud quick start

Deploy the AWS SOAR stack and Snowflake objects:

```powershell
# 1. Configure credentials in .env (see .env.example)
# 2. Deploy AWS SAM stack (Lambda + API Gateway)
sam build --template-file infra/template.yaml
sam deploy --stack-name froststream-soar --parameter-overrides TargetNaclId=acl-xxx TargetVpcId=vpc-xxx ...

# 3. Deploy Snowflake DDL, stages, Snowpipe
snow sql -f snowflake_setup/01_tables.sql -c <conn>
snow sql -f snowflake_setup/02_snowpipe.sql -c <conn>

# 4. Package & upload Snowpark code
python tools/deploy_snowpark_code.py --build --upload

# 5. Deploy SPROCs, external function, tasks
snow sql -f snowflake_setup/03_snowpark_integration.sql -c <conn>

# 6. Start tasks
snow sql -q "ALTER TASK CORE.FLATTEN_FLOW_TASK RESUME; ALTER TASK CORE.INFERENCE_TASK RESUME; ALTER TASK CORE.DRIFT_MONITOR_TASK RESUME; ALTER TASK CORE.SOAR_DISPATCH_TASK RESUME;" -c <conn>
```

## Test and validate

Run the complete automated suite from the repository root:

```powershell
pytest tests/ -v
```

**Current baseline: 82 passing tests.** The suite covers preprocessing, flow aggregation, dual-mode factories, model behavior (ensemble voting, IsolationForest, PSI drift), SQL structure, mitigation idempotency, and mocked real-capture end-to-end paths.

## Repository map

```text
.
├── app.py                         Local Streamlit dashboard entry point
├── data/dataset_loader.py         NSL-KDD schema, labels, and sample generator
├── ingestion/flow_processor.py   Packet aggregation and local/cloud flow sink
├── src/common/execution_mode.py   LOCAL/CLOUD factory and implementations
├── src/models/                    Current ensemble, inference, and drift code
├── src/soar/                      Optional NACL mitigation and cleanup Lambdas
├── storage/                       Generated local alerts, models, and flow data
├── snowflake_setup/               Snowflake schema, pipe, procedures, and checks
├── infra/template.yaml            AWS SAM template for the SOAR stack
├── tools/                         Provisioning, packaging, smoke, and check scripts
├── tests/                         Automated unit, SQL, SOAR, and E2E tests
├── docs/                          Public PMD, implementation plan, operations guide
├── .github/workflows/deploy.yml   GitHub Actions CI/CD (lint/test + SAM + Snowflake)
├── streamlit_app/sis_dashboard.py SiS operational dashboard (real Snowflake queries)
└── README.md
```

## Key documentation

| File | Purpose |
|------|---------|
| `docs/implementation_plan.md` | End-to-end plan with live status, retrain/cost docs |
| `docs/CRITICAL_PATH_VALIDATION_PLAN.md` | Draft plan for DoS/U2R CRITICAL test (requires approval) |
| `docs/TESTING_RUNNING_AWS_SNOWFLAKE_GUIDE.md` | Practical setup, deployment, verification, troubleshooting |
| `docs/design.md` | Dashboard design specification |
| `docs/NIDS-SecOps Project Master Document.md` | Architecture, scope, governance, delivery overview |

## Security and data handling

- Never commit `.env`, private keys, access keys, passwords, or real network captures containing sensitive data.
- Use least-privilege AWS and Snowflake roles. The optional SOAR path changes network controls and must be reviewed before it is enabled.
- Synthetic records are explicitly marked with `IS_SYNTHETIC`; use `CORE.LIVE_FLOW_FEATURES` and `CORE.LIVE_NIDS_ALERTS` for real-traffic reporting.
- The default SOAR response creates a `/32` ingress deny rule in the managed rule range and records a TTL tag. Review rule ranges, NACL placement, and emergency rollback procedures before production use.
- This is an engineering and research implementation, not a certified replacement for a production IDS, SIEM, or incident-response process.

## Current implementation status (as of 2026-09-26)

| Phase | Component | Status |
|-------|-----------|--------|
| 0 | Core ML, dual-mode factory, local dashboard | ✅ DONE |
| 1 | Snowflake DDL, Snowpipe, streams, tasks | ✅ LIVE - VERIFIED |
| 2 | Ensemble + IsolationForest + PSI drift | ✅ DONE |
| 3 | Snowpark SPROCs, external function, orchestration | ✅ LIVE - VERIFIED |
| 4 | Scapy ingestion (bidirectional, dual-mode) | ✅ LIVE - VERIFIED |
| 5 | SOAR Lambda + API Gateway + 24h TTL cleanup | ✅ LIVE - VERIFIED (expiry validated 2026-09-26) |
| 6 | SiS Dashboard (real queries only) | ✅ DONE |
| 7 | CI/CD GitHub Actions | ✅ DONE |
| 8 | Test suite (82 tests) | ✅ DONE |

**All 82 tests passing.** Two live Scapy captures (39 real flows) validated end-to-end. SOAR ACTIONED → SUPPRESSED → EXPIRED lifecycle confirmed. CRITICAL-path test plan drafted (requires approval).

## Known boundaries

- The local dashboard is a Streamlit application; cloud UI deployment is environment-specific.
- Snowflake procedures run on a schedule and are not a per-packet intrusion-prevention function.
- The model is trained from NSL-KDD-compatible data; traffic distributions, protocols, and threats change over time. Monitor drift and validate against representative local traffic.
- Firehose provisioning and VPC Flow Logs delivery are deployment prerequisites, not fully automated by the Python package.
- CI/CD, production change automation, and a full SIEM integration are outside the current documented scope.